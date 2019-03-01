const assert = require('assert');
const { Threshold, PublicKey, PrivateKey, InsecureSignature } = require('../');
const crypto = require('crypto');

describe('Threshold', () => {
   it('Should be able to create verifiable threshold signature', () => {
       // To initialize a T of N threshold key under a
       // Joint-Feldman scheme:
       const T = 2;
       const N = 3;

       // 1. Each player calls PrivateKey::NewThreshold.
       // They send everyone commitment to the polynomial,
       // and send secret share fragments frags[j-1] to
       // the j-th player (All players have index >= 1).

       // PublicKey commits[N][T]
       // PrivateKey frags[N][N]
       const commits = [[]];
       const frags = [[]];
       for (let i = 0; i < N; ++i) {
           commits.push([]);
           frags.push([]);
           for (let j = 0; j < N; ++j) {
               if (j < T) {
                   let g;
                   commits[i].push(PublicKey.fromG1(g));
               }
               let b;
               frags[i].push(PrivateKey.fromBN(b));
           }
       }

       const sk1 = Threshold.create(commits[0], frags[0], T, N);
       const sk2 = Threshold.create(commits[1], frags[1], T, N);
       const sk3 = Threshold.create(commits[2], frags[2], T, N);

       // 2. Each player calls Threshold::VerifySecretFragment
       // on all secret fragments they receive.  If any verify
       // false, they complain to abort the scheme.  (Note that
       // repeatedly aborting, or 'speaking' last, can bias the
       // master public key.)

       for (let target = 1; target <= N; ++target) {
           for (let source = 1; source <= N; ++source) {
               assert(Threshold.verifySecretFragment(target, frags[source-1][target-1], commits[source-1], T));
           }
       }

       // 3. Each player computes the shared, master public key:
       // masterPubkey = PublicKey::AggregateInsecure(...)
       // They also create their secret share from all secret
       // fragments received (now verified):
       // secretShare = PrivateKey::AggregateInsecure(...)

       const masterPubkey = PublicKey.aggregateInsecure([
           commits[0][0], commits[1][0], commits[2][0]
       ]);

       // recvdFrags[j][i] = frags[i][j]
       const recvdFrags = [[]];
       for (let i = 0; i < N; ++i) {
           recvdFrags.push([]);
           for (let j = 0; j < N; ++j) {
               recvdFrags[i].push(frags[j][i]);
           }
       }

       const secretShare1 = PrivateKey.aggregateInsecure(recvdFrags[0]);
       const secretShare2 = PrivateKey.AggregateInsecure(recvdFrags[1]);
       const secretShare3 = PrivateKey.AggregateInsecure(recvdFrags[2]);

       // 4a. Player P creates a pre-multiplied signature share wrt T players:
       // sigShare = Threshold::SignWithCoefficient(...)
       // These signature shares can be combined to sign the msg:
       // signature = InsecureSignature::Aggregate(...)
       // The advantage of this approach is that forming the final signature
       // no longer requires information about the players.

       const msg = Buffer.from([100, 2, 254, 88, 90, 45, 23]);
       const hash = crypto
           .createHash('sha256')
           .update(msg)
           .digest();

       const players = [1, 3];
       // For example, players 1 and 3 sign.
       // As we have verified the coefficients through the commitments given,
       // using InsecureSignature is okay.
       const sigShareC1 = Threshold.signWithCoefficient(secretShare1, msg, 1, players, T);
       const sigShareC3 = Threshold.signWithCoefficient(secretShare3, msg, 3, players, T);

       const signature = InsecureSignature.aggregate([sigShareC1, sigShareC3]);

       assert(signature.verify([hash], [masterPubkey]));

       // 4b. Alternatively, players may sign the message blindly, creating
       // a unit signature share: sigShare = secretShare.SignInsecure(...)
       // These signatures may be combined with lagrange coefficients to
       // sign the message: signature = Threshold::AggregateUnitSigs(...)
       // The advantage to this approach is that each player does not need
       // to know the final list of signatories.

       // For example, players 1 and 3 sign.
       const sigShareU1 = secretShare1.signInsecure(msg);
       const sigShareU3 = secretShare3.signInsecure(msg);
       const signature2 = Threshold.aggregateUnitSigs(
           [sigShareU1, sigShareU3], msg, players, T
       );

       assert(signature2.verify([hash], [masterPubkey]));
   });
});