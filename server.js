// Fires when a customer buys a "Layby Deposit" product. Pulls the real item's
// details (via the deposit product's `custom.layby_target_product` metafield),
// computes the payment schedule, and sends the customer a pre-filled layby
// agreement to review and e-sign through Dropbox Sign.
//
// This does NOT run inside Shopify Flow — see the earlier notes in this
// project on why (Flow's Run code action cannot make HTTP calls or call a
// signature API). It's a standalone webhook server you deploy and host.

import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import Stripe from "stripe";

const {
  SHOPIFY_STORE_DOMAIN, // e.g. mikun-3.myshopify.com
  // Shopify retired static Admin API tokens for new custom apps as of Jan 1,
  // 2026. Apps now authenticate with the client credentials grant: exchange
  // these two values for a short-lived (24hr) token, per request, instead of
  // using one long-lived token forever. Both come from Dev Dashboard → your
  // app → Settings → Credentials.
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  SHOPIFY_WEBHOOK_SECRET,
  SHOPIFY_API_VERSION = "2024-10",
  LAYBY_AGREEMENT_API_BASE = "https://project--78e6e767-1c5d-4be3-8ff7-fbb4cce5ae30-dev.lovable.app",
  LAYBY_AGREEMENT_PAGE_URL = "https://mikun.com/pages/layby-agreement",
  LAYBY_TERM_WEEKS = "16",
  LAYBY_DEPOSIT_SKU_PREFIX = "LAYBY-DEP-",
  // Stripe — the restricted key you created scoped to Checkout Sessions,
  // Products, Prices only (never a full secret key). Starts with rk_live_
  // (or rk_test_ while testing).
  STRIPE_RESTRICTED_KEY,
  // From Stripe Dashboard → Developers → Webhooks, after you register the
  // endpoint below. Used to verify webhook calls are genuinely from Stripe.
  STRIPE_WEBHOOK_SECRET,
  // Where the customer is sent back to after paying / cancelling.
  STOREFRONT_BASE_URL = "https://mikun.com",
  // Shared secret the Shopify Flow "Send HTTP request" action sends as
  // X-Cron-Secret. Must match exactly what's configured in that Flow step.
  CRON_SECRET,
  // Shared secret this server sends on to the Lovable-hosted layby backend
  // (as X-Internal-Secret) when forwarding the weekly reminder trigger.
  // Must match LAYBY_REMINDER_INTERNAL_SECRET set on that project.
  LAYBY_REMINDER_INTERNAL_SECRET,
  // Shared secret the Lovable-hosted layby backend sends (as X-Order-Secret)
  // when it calls back here, after the owner marks a layby paid off, to
  // create the real Shopify sales order. Separate secret, separate
  // direction of trust from LAYBY_REMINDER_INTERNAL_SECRET above.
  LAYBY_ORDER_SECRET,
  PORT = 3000,
} = process.env;

// Only the bare minimum to boot the server and accept Stripe checkout requests.
// Everything else (Dropbox Sign, the /webhooks/orders/create legacy path, the
// Stripe webhook) is checked per-feature below, so this server can go live
// today even before Dropbox Sign is set up — that piece can be added later
// without a redeploy from scratch.
const REQUIRED_TO_BOOT = {
  SHOPIFY_STORE_DOMAIN,
  SHOPIFY_CLIENT_ID,
  SHOPIFY_CLIENT_SECRET,
  STRIPE_RESTRICTED_KEY,
};
for (const [key, value] of Object.entries(REQUIRED_TO_BOOT)) {
  if (!value) {
    console.error(`Missing required environment variable: ${key}. See .env.example.`);
    process.exit(1);
  }
}
if (!STRIPE_WEBHOOK_SECRET) {
  console.warn(
    "STRIPE_WEBHOOK_SECRET not set — /webhooks/stripe will reject all events until this is added (you'll get this value from Stripe after registering the webhook, once this server has a public URL)."
  );
}
if (!SHOPIFY_WEBHOOK_SECRET) {
  console.warn("SHOPIFY_WEBHOOK_SECRET not set — the legacy /webhooks/orders/create path (unused by the current layby flow) will reject all events.");
}
if (!CRON_SECRET) {
  console.warn("CRON_SECRET not set — /api/send-weekly-reminders will reject all requests until this matches the Shopify Flow's X-Cron-Secret header.");
}
if (!LAYBY_REMINDER_INTERNAL_SECRET) {
  console.warn("LAYBY_REMINDER_INTERNAL_SECRET not set — /api/send-weekly-reminders cannot forward to the layby backend until this matches its LAYBY_REMINDER_INTERNAL_SECRET.");
}
if (!LAYBY_ORDER_SECRET) {
  console.warn("LAYBY_ORDER_SECRET not set — /api/create-layby-order will reject all requests until this matches the layby backend's X-Order-Secret header.");
}

const stripe = new Stripe(STRIPE_RESTRICTED_KEY);

const app = express();

// The layby modal's JS runs on mikun.com and calls this server on a
// different origin (onrender.com) — without explicit CORS headers, browsers
// silently block the response ("Failed to fetch"), even though the request
// itself reaches the server fine. Scoped to the storefront's actual domains
// rather than a wildcard, since this handles customer payment intent.
const ALLOWED_ORIGINS = new Set([
  "https://mikun.com",
  "https://www.mikun.com",
  `https://${SHOPIFY_STORE_DOMAIN}`,
]);
app.use((req, res, next) => {
  const origin = req.get("Origin");
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

// Stripe's webhook signature check needs the raw, untouched request body —
// it must be registered BEFORE express.json() parses the body into an
// object, or verification will always fail. Every other route uses the
// regular JSON parser below.
app.post("/webhooks/stripe", express.raw({ type: "application/json" }), handleStripeWebhook);

app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

function verifyWebhook(req) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
  if (!hmacHeader || !req.rawBody) return false;
  const digest = crypto.createHmac("sha256", SHOPIFY_WEBHOOK_SECRET).update(req.rawBody).digest("base64");
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
  } catch {
    return false;
  }
}

// Client credentials grant: exchange CLIENT_ID + CLIENT_SECRET for a token
// good for 24 hours. Cached in memory and refreshed a minute before expiry,
// so normal traffic reuses one token instead of requesting a fresh one on
// every call — Shopify's own reference implementation for this flow does
// the same thing.
let _shopifyToken = null;
let _shopifyTokenExpiresAt = 0;

async function getShopifyAccessToken() {
  if (_shopifyToken && Date.now() < _shopifyTokenExpiresAt - 60_000) {
    return _shopifyToken;
  }
  const res = await fetch(`https://${SHOPIFY_STORE_DOMAIN}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: SHOPIFY_CLIENT_ID,
      client_secret: SHOPIFY_CLIENT_SECRET,
    }),
  });
  if (!res.ok) {
    throw new Error(`Shopify token exchange failed: ${res.status} ${await res.text()}`);
  }
  const { access_token, expires_in } = await res.json();
  _shopifyToken = access_token;
  _shopifyTokenExpiresAt = Date.now() + expires_in * 1000;
  return _shopifyToken;
}

async function adminGraphQL(query, variables = {}) {
  const res = await fetch(`https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": await getShopifyAccessToken(),
    },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(`Admin GraphQL error: ${JSON.stringify(json.errors)}`);
  return json.data;
}

/**
 * Looks up the deposit product's linked real item and its retail price.
 * Requires the deposit product to have a `custom.layby_target_product`
 * metafield (product reference) pointing at the real item. Every new layby
 * deposit product needs this set up manually when it's created — see README.
 */
async function getLaybyTargetProduct(depositProductGid) {
  const query = `
    query GetTarget($id: ID!) {
      product(id: $id) {
        title
        metafield(namespace: "custom", key: "layby_target_product") {
          reference {
            ... on Product {
              id
              title
              priceRangeV2 { minVariantPrice { amount currencyCode } }
            }
          }
        }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: depositProductGid });
  const target = data.product?.metafield?.reference;
  if (!target) {
    throw new Error(
      `Deposit product "${data.product?.title}" (${depositProductGid}) has no custom.layby_target_product metafield set — cannot determine the real item or its price.`
    );
  }
  return {
    id: target.id,
    title: target.title,
    price: parseFloat(target.priceRangeV2.minVariantPrice.amount),
    currency: target.priceRangeV2.minVariantPrice.currencyCode,
  };
}

/**
 * Marks the real item as reserved the moment its layby deposit is bought:
 *   1. Sets custom.reserved to "true" (single_line_text_field — the theme's
 *      Liquid code accepts "yes"/"true"/"1"/"reserved", case-insensitive).
 *   2. Sets the item's inventory to 0 at the store's primary location, so
 *      product.available becomes false and the existing Sold/Reserved
 *      Liquid logic on both the product page and the Bags grid picks it up
 *      automatically — no theme changes needed for this part.
 *
 * This does NOT touch the deposit product's own inventory (it's untracked
 * on purpose, so it stays purchasable indefinitely — see README).
 */
async function reserveTargetProduct(targetProductGid) {
  const query = `
    query GetVariantForReserve($id: ID!) {
      product(id: $id) {
        variants(first: 1) {
          nodes {
            id
            inventoryItem {
              id
              inventoryLevels(first: 1) {
                nodes {
                  location { id }
                  quantities(names: ["available"]) { name quantity }
                }
              }
            }
          }
        }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: targetProductGid });
  const variant = data.product?.variants?.nodes?.[0];
  const level = variant?.inventoryItem?.inventoryLevels?.nodes?.[0];
  if (!variant || !level) {
    throw new Error(`Could not find an inventory level for target product ${targetProductGid} — is inventory tracking enabled on it?`);
  }
  const currentQty = level.quantities.find((q) => q.name === "available")?.quantity ?? 0;
  const locationId = level.location.id;

  const setQtyMutation = `
    mutation SetZero($input: InventorySetQuantitiesInput!) {
      inventorySetQuantities(input: $input) {
        userErrors { field message }
      }
    }
  `;
  const setQtyResult = await adminGraphQL(setQtyMutation, {
    input: {
      name: "available",
      reason: "other",
      ignoreCompareQuantity: true,
      quantities: [{ inventoryItemId: variant.inventoryItem.id, locationId, quantity: 0 }],
    },
  });
  if (setQtyResult.inventorySetQuantities.userErrors.length) {
    throw new Error(`Failed to zero inventory: ${JSON.stringify(setQtyResult.inventorySetQuantities.userErrors)}`);
  }

  const setMetafieldMutation = `
    mutation SetReserved($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        userErrors { field message }
      }
    }
  `;
  const setMetafieldResult = await adminGraphQL(setMetafieldMutation, {
    metafields: [{ ownerId: targetProductGid, namespace: "custom", key: "reserved", type: "single_line_text_field", value: "Yes" }],
  });
  if (setMetafieldResult.metafieldsSet.userErrors.length) {
    throw new Error(`Failed to set custom.reserved: ${JSON.stringify(setMetafieldResult.metafieldsSet.userErrors)}`);
  }

  console.log(`Reserved ${targetProductGid}: inventory zeroed (was ${currentQty}), custom.reserved set to "Yes".`);
}

async function getOrderDetails(orderGid) {
  const query = `
    query GetOrder($id: ID!) {
      order(id: $id) {
        id
        name
        createdAt
        customer { firstName lastName email }
        lineItems(first: 10) {
          edges {
            node {
              sku
              originalUnitPriceSet { shopMoney { amount } }
              product { id title }
            }
          }
        }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: orderGid });
  return data.order;
}

async function createAgreementLink({ customerName, customerEmail, customerPhone, productGid, itemTitle, orderReference, totalPrice, depositAmount, currency, agreementDate, dueDate }) {
  // Calls our own Lovable-hosted agreement app: creates a layby record and
  // returns a private token. The customer signs on our own site (mikun.com)
  // rather than a third-party e-signature tool — no email roundtrip needed.
  const res = await fetch(`${LAYBY_AGREEMENT_API_BASE}/api/public/layby-intake`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      product_gid: productGid,
      item_title: itemTitle,
      item_reference: orderReference,
      total_price: totalPrice,
      deposit_amount: depositAmount,
      currency,
      customer_name: customerName,
      customer_email: customerEmail,
      customer_phone: customerPhone || "",
      agreement_date: agreementDate.toISOString(),
      balance_due_date: dueDate.toISOString(),
      term_weeks: parseInt(LAYBY_TERM_WEEKS, 10),
    }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Layby agreement intake error: ${JSON.stringify(json)}`);
  }
  // json.token is the private key; build the on-site signing URL ourselves
  // rather than trusting any URL the intake API might return, since only
  // mikun.com should ever be linked to a customer.
  const signingUrl = `${LAYBY_AGREEMENT_PAGE_URL}?id=${encodeURIComponent(json.token)}`;
  return { token: json.token, reference: json.reference, signingUrl };
}

app.post("/webhooks/orders/create", async (req, res) => {
  if (!verifyWebhook(req)) {
    return res.status(401).send("Invalid webhook signature");
  }
  res.status(200).send("ok"); // acknowledge immediately, do the work after

  try {
    const orderPayload = req.body;
    const orderGid = `gid://shopify/Order/${orderPayload.id}`;
    const order = await getOrderDetails(orderGid);

    const depositLineItem = order.lineItems.edges
      .map((e) => e.node)
      .find((li) => li.sku && li.sku.startsWith(LAYBY_DEPOSIT_SKU_PREFIX));

    if (!depositLineItem) {
      console.log(`Order ${order.name}: no layby deposit line item, skipping.`);
      return;
    }
    if (!order.customer?.email) {
      console.log(`Order ${order.name}: no customer email on file, cannot send agreement.`);
      return;
    }

    const target = await getLaybyTargetProduct(depositLineItem.product.id);

    // Reserve the real item immediately — do this before sending the
    // agreement so the item can never be sold to someone else in the gap
    // between "deposit paid" and "agreement sent", even if the signature
    // request below fails or is slow.
    await reserveTargetProduct(target.id);

    const depositAmount = parseFloat(depositLineItem.originalUnitPriceSet.shopMoney.amount);
    const agreementDate = new Date(order.createdAt);
    const dueDate = new Date(agreementDate);
    dueDate.setDate(dueDate.getDate() + parseInt(LAYBY_TERM_WEEKS, 10) * 7);

    const customerName = [order.customer.firstName, order.customer.lastName].filter(Boolean).join(" ") || "Customer";

    const agreement = await createAgreementLink({
      customerName,
      customerEmail: order.customer.email,
      productGid: target.id,
      itemTitle: target.title,
      orderReference: order.name,
      totalPrice: target.price,
      depositAmount,
      currency: target.currency,
      agreementDate,
      dueDate,
    });

    console.log(`Order ${order.name}: layby agreement created (reference ${agreement.reference}) — ${agreement.signingUrl}`);
  } catch (err) {
    console.error("Error processing order webhook:", err);
  }
});

/**
 * Looks up a product's real, current price and title directly from Shopify
 * by its GID. Deliberately NEVER trusts a price sent from the browser —
 * the theme only ever sends us which product the customer is looking at;
 * this function is the single source of truth for what it actually costs,
 * so nobody can tamper with the deposit amount client-side.
 */
async function getProductForCheckout(productGid) {
  const query = `
    query GetProductForCheckout($id: ID!) {
      product(id: $id) {
        title
        metafields(namespace: "custom", first: 5) {
          nodes { key value }
        }
        priceRangeV2 { minVariantPrice { amount currencyCode } }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: productGid });
  if (!data.product) {
    throw new Error(`Product ${productGid} not found.`);
  }
  const ref = data.product.metafields.nodes.find((m) => m.key === "serial_number")?.value;
  return {
    title: data.product.title,
    price: parseFloat(data.product.priceRangeV2.minVariantPrice.amount),
    currency: data.product.priceRangeV2.minVariantPrice.currencyCode,
    reference: ref || productGid,
  };
}

/**
 * Called by the "Put It On Layby" modal when the customer submits the form.
 * Creates a Stripe Checkout Session for exactly 20% of the item's real,
 * server-verified price and returns its URL for the browser to redirect to.
 *
 * Nothing is reserved or emailed at this point — that only happens once
 * Stripe confirms the payment actually succeeded, via the webhook below.
 */
app.post("/api/create-layby-checkout", async (req, res) => {
  try {
    const { productGid, customerName, customerEmail, customerPhone, note } = req.body;
    if (!productGid || !customerName || !customerEmail) {
      return res.status(400).json({ error: "productGid, customerName and customerEmail are required." });
    }

    const product = await getProductForCheckout(productGid);
    const depositAmount = Math.round(product.price * 0.2 * 100) / 100; // 20%, rounded to cents
    const currency = product.currency.toLowerCase();

    const agreementDate = new Date();
    const dueDate = new Date(agreementDate);
    dueDate.setDate(dueDate.getDate() + parseInt(LAYBY_TERM_WEEKS, 10) * 7);

    // Created before checkout, not after, so the moment the deposit clears
    // Stripe can send the customer straight to their own agreement page —
    // no separate email round trip needed. The item itself is only ever
    // reserved later, from the payment webhook below, once money has
    // actually moved — never from this step.
    let agreement;
    try {
      agreement = await createAgreementLink({
        customerName,
        customerEmail,
        customerPhone,
        productGid,
        itemTitle: product.title,
        orderReference: product.reference,
        totalPrice: product.price,
        depositAmount,
        currency: currency.toUpperCase(),
        agreementDate,
        dueDate,
      });
    } catch (agreementErr) {
      console.error("Could not create layby agreement record — falling back to enquiry flow:", agreementErr);
      return res.status(502).json({ error: "Could not prepare your layby agreement. Please try again or contact us directly." });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: customerEmail,
      // Collected now, at deposit time, so the shipping address is already
      // on file by the time the layby is eventually paid off — the
      // "mark paid off" link can then generate a fully shippable Shopify
      // order without asking the owner to type anything in. Edit
      // allowed_countries below if MIKUN starts shipping laybys overseas.
      shipping_address_collection: { allowed_countries: ["NZ"] },
      line_items: [
        {
          price_data: {
            currency,
            product_data: {
              name: `Layby Deposit — ${product.title}`,
              description: `20% deposit. Reference ${product.reference}. Balance due over ${LAYBY_TERM_WEEKS} weeks.`,
            },
            unit_amount: Math.round(depositAmount * 100), // Stripe wants the smallest currency unit
          },
          quantity: 1,
        },
      ],
      success_url: agreement.signingUrl,
      cancel_url: `${STOREFRONT_BASE_URL}/products/${product.handle || ""}`,
      metadata: {
        mikun_flow: "layby_deposit",
        product_gid: productGid,
        product_title: product.title,
        product_reference: product.reference,
        full_price: String(product.price),
        deposit_amount: String(depositAmount),
        customer_name: customerName,
        customer_phone: customerPhone || "",
        note: (note || "").slice(0, 400),
        layby_agreement_token: agreement.token,
        layby_agreement_reference: agreement.reference,
      },
    });

    res.status(200).json({ url: session.url });
  } catch (err) {
    console.error("Error creating layby checkout session:", err);
    res.status(500).json({ error: "Could not create checkout session." });
  }
});

/**
 * Fires once Stripe confirms the deposit was actually paid. This is the
 * ONLY point in the whole flow where money has genuinely changed hands —
 * everything before this (the modal, the checkout redirect) could be
 * abandoned at any point, so reservation and the agreement must wait
 * until this event, not the form submission.
 */
async function handleStripeWebhook(req, res) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Stripe webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook signature verification failed.`);
  }

  res.status(200).send("ok"); // acknowledge immediately, do the work after

  if (event.type !== "checkout.session.completed") return;

  const session = event.data.object;
  if (session.metadata?.mikun_flow !== "layby_deposit") return; // not one of ours

  try {
    const {
      product_gid: productGid,
      product_title: itemTitle,
      layby_agreement_reference: agreementReference,
      layby_agreement_token: agreementToken,
    } = session.metadata;

    // Reserve the real item now that money has actually moved. The
    // agreement record itself was already created back when the checkout
    // session was created (see /api/create-layby-checkout) — Stripe's
    // success_url already sent the customer straight to it, so there's
    // nothing left to send from here.
    await reserveTargetProduct(productGid);

    console.log(
      `Stripe checkout ${session.id}: deposit paid, ${itemTitle} reserved, agreement ${agreementReference || "(reference unknown)"} awaiting signature.`
    );

        // Save the shipping address Stripe just collected onto the agreement
        // record, so it's already there by the time the layby is eventually
        // paid off and a real Shopify order gets created from it — see
        // /api/create-layby-order below. Best-effort: never let a problem here
        // undo the reservation above or bounce the webhook back to Stripe.
        //
        // Stripe moved this from the top-level `shipping_details` field to
        // `collected_information.shipping_details` on newer API versions —
        // checking both keeps this working regardless of which version a
        // given webhook destination delivers.
        const shipping = session.collected_information?.shipping_details?.address || session.shipping_details?.address;
        if (shipping && agreementToken && LAYBY_REMINDER_INTERNAL_SECRET) {
                try {
                          const upstream = await fetch(`${LAYBY_AGREEMENT_API_BASE}/api/public/layby-shipping-address`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Internal-Secret": LAYBY_REMINDER_INTERNAL_SECRET },
          body: JSON.stringify({
            token: agreementToken,
            address: {
              address1: shipping.line1 || "",
              address2: shipping.line2 || "",
              city: shipping.city || "",
              province: shipping.state || "",
              zip: shipping.postal_code || "",
              country: shipping.country || "NZ",
            },
          }),
        });
        if (!upstream.ok) {
          console.error(`Saving shipping address for agreement ${agreementReference} failed: ${upstream.status} ${await upstream.text()}`);
        }
      } catch (shippingErr) {
        console.error(`Error saving shipping address for agreement ${agreementReference}:`, shippingErr);
      }
    } else if (!shipping) {
      console.warn(`Stripe checkout ${session.id} completed with no shipping address collected — check shipping_address_collection is still enabled.`);
    }
  } catch (err) {
    console.error("Error processing Stripe checkout.session.completed:", err);
  }
}

/**
 * Fired weekly by the Shopify Flow "Scheduled time" trigger. This server
 * has no direct database access to the layby records (those live in
 * Supabase, behind the Lovable-hosted agreement backend) — its only job
 * here is to check the secret the Flow sends, then forward the trigger
 * on to that backend's own protected endpoint, which does the actual
 * query-and-send work. Two separate secrets on purpose: a leak of the
 * Flow-facing one doesn't expose the Lovable-facing one, or vice versa.
 */
app.post("/api/send-weekly-reminders", async (req, res) => {
  if (!CRON_SECRET || req.get("X-Cron-Secret") !== CRON_SECRET) {
    return res.status(401).json({ error: "Invalid or missing X-Cron-Secret" });
  }
  if (!LAYBY_REMINDER_INTERNAL_SECRET) {
    console.error("Cannot forward weekly reminder trigger: LAYBY_REMINDER_INTERNAL_SECRET is not configured.");
    return res.status(500).json({ error: "Server not configured to forward reminder trigger." });
  }

  try {
    // NOTE: this is /api/public/... not /api/internal/... — Lovable's
    // hosting platform blocks every /api/internal/* route with a hard 403
    // on the public domain, regardless of app-level auth. Real protection
    // here comes entirely from the X-Internal-Secret header, not the path.
    const upstream = await fetch(`${LAYBY_AGREEMENT_API_BASE}/api/public/send-weekly-reminders`, {
      method: "POST",
      headers: { "X-Internal-Secret": LAYBY_REMINDER_INTERNAL_SECRET },
    });
    const body = await upstream.text();
    console.log(`Weekly reminder trigger forwarded: upstream responded ${upstream.status} ${body}`);
    res.status(upstream.status).type(upstream.headers.get("content-type") || "text/plain").send(body);
  } catch (err) {
    console.error("Error forwarding weekly reminder trigger:", err);
    res.status(502).json({ error: "Could not reach layby agreement backend." });
  }
});

/**
 * Looks up the first variant of the real item, so a genuine Shopify order
 * line item can point at it. Layby items are one-of-a-kind (see
 * reserveTargetProduct above), so "first variant" is always the right one.
 */
async function getVariantForOrder(productGid) {
  const query = `
    query GetVariantForOrder($id: ID!) {
      product(id: $id) {
        title
        variants(first: 1) {
          nodes { id }
        }
      }
    }
  `;
  const data = await adminGraphQL(query, { id: productGid });
  const variant = data.product?.variants?.nodes?.[0];
  if (!variant) {
    throw new Error(`Product ${productGid} has no variants — cannot create an order line item for it.`);
  }
  return { variantId: variant.id, title: data.product.title };
}

/**
 * Fired by the Lovable-hosted layby backend right after the owner clicks a
 * "mark paid off" link. Creates the real Shopify sales order for record-
 * keeping (and, when a shipping address is supplied, for fulfillment) —
 * this is the ONLY place a layby ever becomes a genuine Shopify order; the
 * deposit itself only ever went through Stripe (see /api/create-layby-checkout
 * above), so nothing else in this system has created one before now.
 *
 * inventoryBehaviour is BYPASS because the real item's inventory was already
 * zeroed out at deposit time (see reserveTargetProduct) — this order must
 * not try to decrement it again.
 *
 * financialStatus is PAID and a matching SALE transaction is attached
 * because, by the time this fires, the full price has genuinely been
 * collected already (the deposit via Stripe, the balance via bank transfer
 * reconciled by hand) — this is a record of money already received, not a
 * new charge.
 */
app.post("/api/create-layby-order", async (req, res) => {
  if (!LAYBY_ORDER_SECRET || req.get("X-Order-Secret") !== LAYBY_ORDER_SECRET) {
    return res.status(401).json({ error: "Invalid or missing X-Order-Secret" });
  }

  const {
    reference, // layby reference, e.g. MK-LB-EG2YSF — recorded on the order for traceability
    productGid,
    customerName,
    customerEmail,
    customerPhone,
    totalPrice,
    currency,
    shippingAddress, // optional: { address1, address2, city, provinceCode, zip, countryCode }
  } = req.body || {};

  if (!productGid || !customerEmail || !totalPrice || !currency) {
    return res.status(400).json({ error: "productGid, customerEmail, totalPrice and currency are required." });
  }

  try {
    const { variantId, title } = await getVariantForOrder(productGid);

    const [firstName, ...rest] = (customerName || "").trim().split(/\s+/).filter(Boolean);
    const lastName = rest.join(" ") || undefined;

    const amount = String(totalPrice);
    const currencyCode = String(currency).toUpperCase();

    const orderInput = {
      email: customerEmail,
      phone: customerPhone || undefined,
      lineItems: [
        {
          variantId,
          quantity: 1,
          // Locks in the exact price the customer agreed to in the layby
          // agreement, rather than whatever the item happens to be priced
          // at in Shopify by the time it's finally paid off.
          priceSet: { shopMoney: { amount, currencyCode } },
        },
      ],
      customer: {
        toUpsert: {
          email: customerEmail,
          firstName: firstName || undefined,
          lastName,
          phone: customerPhone || undefined,
        },
      },
      financialStatus: "PAID",
      transactions: [
        {
          kind: "SALE",
          status: "SUCCESS",
          gateway: "Layby (deposit + balance)",
          amountSet: { shopMoney: { amount, currencyCode } },
        },
      ],
      note: `Layby ${reference || ""} — paid off in full (deposit via Stripe, balance reconciled by hand).`.trim(),
      tags: ["layby", "layby-paid-in-full"],
    };

    if (shippingAddress && shippingAddress.address1) {
      orderInput.shippingAddress = {
        firstName: firstName || undefined,
        lastName,
        phone: customerPhone || undefined,
        address1: shippingAddress.address1,
        address2: shippingAddress.address2 || undefined,
        city: shippingAddress.city || undefined,
        provinceCode: shippingAddress.provinceCode || undefined,
        zip: shippingAddress.zip || undefined,
        countryCode: shippingAddress.countryCode || "NZ",
      };
    }

    const mutation = `
      mutation CreateLaybyOrder($order: OrderCreateOrderInput!, $options: OrderCreateOptionsInput) {
        orderCreate(order: $order, options: $options) {
          order { id name }
          userErrors { field message }
        }
      }
    `;
    const data = await adminGraphQL(mutation, {
      order: orderInput,
      options: {
        inventoryBehaviour: "BYPASS",
        sendReceipt: false,
        sendFulfillmentReceipt: false,
      },
    });

    const { order, userErrors } = data.orderCreate;
    if (userErrors && userErrors.length) {
      console.error(`orderCreate failed for layby ${reference}:`, JSON.stringify(userErrors));
      return res.status(422).json({ error: "Shopify rejected the order.", details: userErrors });
    }

    console.log(`Created Shopify order ${order.name} (${order.id}) for layby ${reference} — ${title}, ${currencyCode} ${amount}.`);
    res.status(200).json({ orderId: order.id, orderName: order.name });
  } catch (err) {
    console.error(`Error creating Shopify order for layby ${reference}:`, err);
    res.status(500).json({ error: "Could not create the Shopify order." });
  }
});

app.get("/healthz", (_req, res) => res.status(200).send("ok"));

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
