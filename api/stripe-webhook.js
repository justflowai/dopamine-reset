/**
 * Vercel Serverless Function: Stripe Webhook -> MailerLite
 *
 * When a Stripe checkout.session.completed event fires,
 * this adds the buyer's email to MailerLite "Buyers" group.
 *
 * Required Vercel Environment Variables:
 *   STRIPE_WEBHOOK_SECRET  - from Stripe Dashboard > Webhooks
 *   MAILERLITE_API_KEY     - from MailerLite > Integrations > API
 *   MAILERLITE_BUYER_GROUP_ID - from MailerLite > Subscribers > Groups
 */

const crypto = require('crypto');

function verifyStripeSignature(payload, sigHeader, secret) {
  const elements = sigHeader.split(',');
  const timestamp = elements.find(e => e.startsWith('t=')).split('=')[1];
  const signature = elements.find(e => e.startsWith('v1=')).split('=')[1];
  const signedPayload = timestamp + '.' + payload;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signedPayload, 'utf8')
    .digest('hex');
  const a = Buffer.from(signature, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function addToMailerLite(email, name, groupId, apiKey) {
  const res = await fetch('https://connect.mailerlite.com/api/subscribers', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + apiKey,
    },
    body: JSON.stringify({
      email: email,
      fields: { name: name || '' },
      groups: [groupId],
      status: 'active',
    }),
  });
  if (!res.ok) {
    const errBody = await res.text();
    throw new Error('MailerLite API error ' + res.status + ': ' + errBody);
  }
  return await res.json();
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const {
    STRIPE_WEBHOOK_SECRET,
    MAILERLITE_API_KEY,
    MAILERLITE_BUYER_GROUP_ID,
  } = process.env;

  if (!STRIPE_WEBHOOK_SECRET || !MAILERLITE_API_KEY || !MAILERLITE_BUYER_GROUP_ID) {
    console.error('Missing environment variables');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  const rawBody = Buffer.concat(chunks).toString('utf8');

  const sigHeader = req.headers['stripe-signature'];
  if (!sigHeader) {
    return res.status(400).json({ error: 'Missing stripe-signature header' });
  }

  try {
    const valid = verifyStripeSignature(rawBody, sigHeader, STRIPE_WEBHOOK_SECRET);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
  } catch (err) {
    console.error('Signature verification failed:', err.message);
    return res.status(401).json({ error: 'Signature verification failed' });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  if (event.type !== 'checkout.session.completed') {
    return res.status(200).json({ received: true, action: 'ignored' });
  }

  const session = event.data.object;
  const email = (session.customer_details && session.customer_details.email) || session.customer_email;
  const name = (session.customer_details && session.customer_details.name) || '';

  if (!email) {
    console.error('No email in checkout session:', session.id);
    return res.status(200).json({ received: true, action: 'no_email' });
  }

  try {
    const result = await addToMailerLite(email, name, MAILERLITE_BUYER_GROUP_ID, MAILERLITE_API_KEY);
    console.log('Added ' + email + ' to Buyers group:', result.data && result.data.id);
    return res.status(200).json({ received: true, action: 'added_to_mailerlite', email: email });
  } catch (err) {
    console.error('Failed to add to MailerLite:', err.message);
    return res.status(200).json({ received: true, action: 'mailerlite_error', error: err.message });
  }
};

module.exports.config = { api: { bodyParser: false } };
