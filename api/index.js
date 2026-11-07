const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');

// Initialize Firebase Admin (Assumes GOOGLE_APPLICATION_CREDENTIALS environment variable is set)
admin.initializeApp();
const db = admin.firestore();

const app = express();

// Middleware to parse JSON and capture raw body for Cashfree webhook signature verification
app.use(express.json({
    verify: (req, res, buf) => {
        if (req.originalUrl === '/webhook/cashfree') {
            req.rawBody = buf;
        }
    }
}));
app.use(cors());

// Authentication Middleware: Verify Firebase ID Token
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

// --------------------------------------------------
// AUTHENTICATION
// --------------------------------------------------
app.post('/auth/signup', authenticate, async (req, res) => {
    try {
        const { uid, username, email, referralCode } = req.body;
        
        // Ensure the token UID matches the requested UID
        if (uid !== req.user.uid) return res.status(403).json({ error: 'Forbidden: UID mismatch' });

        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            await userRef.set({
                username,
                email,
                wallet: 0,
                totalXP: 0,
                joinedMatches: [],
                referralCode: referralCode || crypto.randomBytes(4).toString('hex').toUpperCase(),
                matchesPlayed: 0,
                totalKills: 0,
                dailyStreak: 0,
                lastDailyReward: null,
                isVIP: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
        }
        res.status(200).json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------------------------------------
// PAYMENT GATEWAY: CREATE ORDER
// --------------------------------------------------
app.post('/wallet/createOrder', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const orderId = `ORDER_${req.user.uid}_${Date.now()}`;
        
        // 1. Create Cashfree Order payload
        const cashfreePayload = {
            order_id: orderId,
            order_amount: amount,
            order_currency: "INR",
            customer_details: {
                customer_id: req.user.uid,
                customer_phone: "9999999999" // Can be dynamically pulled from user profile
            },
            order_meta: {
                return_url: "https://your-frontend.com/payment/return?order_id={order_id}"
            }
        };

        // 2. Hit Cashfree API
        const response = await axios.post(`${process.env.CASHFREE_BASE_URL || 'https://sandbox.cashfree.com/pg'}/orders`, cashfreePayload, {
            headers: {
                'x-client-id': process.env.CASHFREE_APP_ID,
                'x-client-secret': process.env.CASHFREE_SECRET_KEY,
                'x-api-version': '2022-09-01',
                'Content-Type': 'application/json'
            }
        });

        // 3. Store transaction in Firestore as PENDING (Do not update wallet yet)
        const txRef = db.collection('transactions').doc(orderId);
        await txRef.set({
            userId: req.user.uid,
            type: 'DEPOSIT',
            amount: amount,
            status: 'PENDING',
            orderId: orderId,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(200).json({ paymentSessionId: response.data.payment_session_id, orderId });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------------------------------------
// PAYMENT GATEWAY: WEBHOOK (VERIFICATION & WALLET UPDATE)
// --------------------------------------------------
app.post('/webhook/cashfree', async (req, res) => {
    try {
        const signature = req.headers['x-webhook-signature'];
        const timestamp = req.headers['x-webhook-timestamp'];
        
        if (!signature || !timestamp || !req.rawBody) {
            return res.status(400).json({ error: 'Missing webhook security parameters' });
        }

        // Verify Signature
        const body = req.rawBody.toString('utf8');
        const data = timestamp + body;
        const expectedSignature = crypto.createHmac('sha256', process.env.CASHFREE_SECRET_KEY)
                                      .update(data)
                                      .digest('base64');
                                      
        if (signature !== expectedSignature) {
            return res.status(401).json({ error: 'Invalid signature' });
        }

        const payload = req.body;
        const orderId = payload.data.order.order_id;
        const txStatus = payload.data.payment.payment_status; // e.g. "SUCCESS" or "FAILED"

        const txRef = db.collection('transactions').doc(orderId);

        // Process idempotently with Firestore transaction
        await db.runTransaction(async (transaction) => {
            const txDoc = await transaction.get(txRef);
            if (!txDoc.exists) throw new Error('Transaction not found');
            
            const txData = txDoc.data();
            if (txData.status !== 'PENDING') return; // Idempotent block

            if (txStatus === 'SUCCESS') {
                const userRef = db.collection('users').doc(txData.userId);
                
                // Credit wallet and mark success
                transaction.update(userRef, {
                    wallet: admin.firestore.FieldValue.increment(txData.amount)
                });
                transaction.update(txRef, { status: 'SUCCESS' });
            } else {
                // Mark failed
                transaction.update(txRef, { status: 'FAILED' });
            }
        });

        res.status(200).send('OK');
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------------------------------------
// MATCH JOIN
// --------------------------------------------------
app.post('/match/join', authenticate, async (req, res) => {
    try {
        const { matchId, gameUids } = req.body;
        const uid = req.user.uid;

        if (!matchId || !gameUids || !Array.isArray(gameUids) || gameUids.length === 0) {
            return res.status(400).json({ error: 'Invalid input' });
        }

        const matchRef = db.collection('matches').doc(matchId);
        const userRef = db.collection('users').doc(uid);
        const teamRef = matchRef.collection('teams').doc(uid);

        await db.runTransaction(async (transaction) => {
            const matchDoc = await transaction.get(matchRef);
            const userDoc = await transaction.get(userRef);
            const teamDoc = await transaction.get(teamRef);

            if (!matchDoc.exists) throw new Error('Match not found');
            if (!userDoc.exists) throw new Error('User not found');
            if (teamDoc.exists) throw new Error('Already joined this match');

            const matchData = matchDoc.data();
            const userData = userDoc.data();

            if (matchData.status !== 'upcoming') throw new Error('Match is not upcoming');
            if (matchData.joinedCount >= matchData.maxPlayers) throw new Error('Match is full');
            
            const entryFee = matchData.entryFee || 0;
            if (userData.wallet < entryFee) throw new Error('Insufficient wallet balance');

            // Duplicate checks within match for specific gameUids
            const registeredGameUids = matchData.registeredGameUids || [];
            for (const gUid of gameUids) {
                if (registeredGameUids.includes(gUid)) {
                    throw new Error(`Game UID ${gUid} is already registered in this match`);
                }
            }

            // Deduct wallet and add to user's joinedMatches
            transaction.update(userRef, {
                wallet: userData.wallet - entryFee,
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
            });

            // Update match state
            transaction.update(matchRef, {
                joinedCount: admin.firestore.FieldValue.increment(1),
                registeredGameUids: admin.firestore.FieldValue.arrayUnion(...gameUids)
            });

            // Create team subcollection document
            transaction.set(teamRef, {
                ownerUid: uid,
                ownerUsername: userData.username,
                gameUids: gameUids,
                joinedAt: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// --------------------------------------------------
// DAILY REWARDS
// --------------------------------------------------
app.post('/rewards/daily', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        const userRef = db.collection('users').doc(uid);

        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) throw new Error('User not found');
            
            const userData = userDoc.data();
            const now = new Date();
            const lastReward = userData.lastDailyReward ? userData.lastDailyReward.toDate() : new Date(0);
            
            const diffTime = Math.abs(now - lastReward);
            const diffHours = diffTime / (1000 * 60 * 60); 
            
            if (diffHours < 24) throw new Error('Daily reward already claimed');

            const isStreakContinuous = diffHours <= 48;
            const newStreak = isStreakContinuous ? (userData.dailyStreak || 0) + 1 : 1;
            const rewardAmount = 10; // e.g., 10 units of currency

            transaction.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(rewardAmount),
                dailyStreak: newStreak,
                lastDailyReward: admin.firestore.FieldValue.serverTimestamp()
            });

            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: uid,
                type: 'DAILY_REWARD',
                amount: rewardAmount,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// --------------------------------------------------
// WITHDRAWAL
// --------------------------------------------------
app.post('/wallet/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        if (!amount || amount <= 0 || !upiId) return res.status(400).json({ error: 'Invalid input' });

        const uid = req.user.uid;
        const userRef = db.collection('users').doc(uid);

        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) throw new Error('User not found');
            
            const userData = userDoc.data();
            if (userData.wallet < amount) throw new Error('Insufficient wallet balance');

            // Immediately deduct/lock funds
            transaction.update(userRef, {
                wallet: userData.wallet - amount
            });

            // Create PENDING withdrawal for admin approval
            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: uid,
                type: 'WITHDRAWAL',
                amount: amount,
                upiId: upiId,
                status: 'PENDING',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// --------------------------------------------------
// MATCH REWARD DISTRIBUTION (ADMIN)
// --------------------------------------------------
app.post('/admin/match/distribute', authenticate, async (req, res) => {
    try {
        // Enforce admin logic - in production check custom claims or admin flags
        if (req.user.email !== process.env.ADMIN_EMAIL) {
             return res.status(403).json({ error: 'Forbidden: Admin access required' });
        }

        const { matchId, gameUid, rank, kills } = req.body;
        if (!matchId || !gameUid || rank == null || kills == null) return res.status(400).json({ error: 'Invalid input' });

        const matchRef = db.collection('matches').doc(matchId);
        const teamsSnapshot = await matchRef.collection('teams').where('gameUids', 'array-contains', gameUid).get();
        
        if (teamsSnapshot.empty) return res.status(404).json({ error: 'Team/Player not found in match' });
        
        const teamDoc = teamsSnapshot.docs[0];
        const teamData = teamDoc.data();
        const ownerUid = teamData.ownerUid;

        const userRef = db.collection('users').doc(ownerUid);
        const prizeRef = teamDoc.ref.collection('prizes').doc(gameUid);

        await db.runTransaction(async (transaction) => {
            const matchDoc = await transaction.get(matchRef);
            if (!matchDoc.exists) throw new Error('Match not found');
            
            const matchData = matchDoc.data();
            const prizeDoc = await transaction.get(prizeRef);
            if (prizeDoc.exists) throw new Error('Prize already distributed for this gameUid');

            const perKillRate = matchData.perKillRate || 0;
            const rankPrize = (matchData.rankPrizes && matchData.rankPrizes[rank.toString()]) ? matchData.rankPrizes[rank.toString()] : 0;
            
            const totalPrize = (kills * perKillRate) + rankPrize;
            const earnedXP = (kills * 10) + Math.floor(100 / rank); // Consistent formula

            // Register prize distributed flag per gameUid
            transaction.set(prizeRef, {
                kills,
                rank,
                prize: totalPrize,
                xp: earnedXP,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            // Credit User
            transaction.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(totalPrize),
                totalXP: admin.firestore.FieldValue.increment(earnedXP),
                totalKills: admin.firestore.FieldValue.increment(kills),
                matchesPlayed: admin.firestore.FieldValue.increment(1)
            });

            // Record Transaction
            const txRef = db.collection('transactions').doc();
            transaction.set(txRef, {
                userId: ownerUid,
                type: 'MATCH_PRIZE',
                amount: totalPrize,
                matchId: matchId,
                gameUid: gameUid,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.status(200).json({ success: true });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
          
