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
  DOCUSEAL_API_KEY,
  DOCUSEAL_TEMPLATE_ID,
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
if (!DOCUSEAL_API_KEY || !DOCUSEAL_TEMPLATE_ID) {
  console.warn(
    "DOCUSEAL_API_KEY / DOCUSEAL_TEMPLATE_ID not set — deposit payments will be accepted and items reserved, but the layby agreement won't be sent until these are added."
  );
}
if (!STRIPE_WEBHOOK_SECRET) {
  console.warn(
    "STRIPE_WEBHOOK_SECRET not set — /webhooks/stripe will reject all events until this is added (you'll get this value from Stripe after registering the webhook, once this server has a public URL)."
  );
}
if (!SHOPIFY_WEBHOOK_SECRET) {
  console.warn("SHOPIFY_WEBHOOK_SECRET not set — the legacy /webhooks/orders/create path (unused by the current layby flow) will reject all events.");
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

function formatDate(d) {
  return d.toLocaleDateString("en-NZ", { day: "2-digit", month: "2-digit", year: "numeric" });
}

function money(amount, currency) {
  return new Intl.NumberFormat("en-NZ", { style: "currency", currency }).format(amount);
}

async function sendForSignature({ customerName, customerEmail, customerPhone, itemTitle, orderReference, totalPrice, depositAmount, currency, agreementDate, dueDate }) {
  const balance = totalPrice - depositAmount;

  // Field names below MUST exactly match the field names set on the
  // DocuSeal template (Templates → MIKUN Layby Sale Agreement → each
  // field's name in the right-hand panel). Signature and date fields are
  // deliberately left out of "values" — those are filled in by the signer
  // at signing time, not prefilled by the server.
  const values = {
    agreement_date: formatDate(agreementDate),
    customer_name: customerName,
    customer_email: customerEmail,
    customer_phone: customerPhone || "",
    item_description: itemTitle,
    product_reference: orderReference,
    total_price: money(totalPrice, currency),
    deposit_amount: money(depositAmount, currency),
    balance_amount: money(balance, currency),
    balance_due_date: formatDate(dueDate),
  };

  const res = await fetch("https://api.docuseal.com/submissions", {
    method: "POST",
    headers: {
      "X-Auth-Token": DOCUSEAL_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      template_id: Number(DOCUSEAL_TEMPLATE_ID),
      send_email: true,
      order: "preserved",
      message: {
        subject: `Your MIKUN layby agreement — ${itemTitle}`,
        body: "Please review and sign your layby agreement below. Once signed, we'll hold your item and be in touch about your payment plan.",
      },
      submitters: [
        {
          role: "First Party",
          name: customerName,
          email: customerEmail,
          values,
        },
      ],
    }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(`DocuSeal error: ${JSON.stringify(json)}`);
  }
  return json;
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

    const result = await sendForSignature({
      customerName,
      customerEmail: order.customer.email,
      itemTitle: target.title,
      orderReference: order.name,
      totalPrice: target.price,
      depositAmount,
      currency: target.currency,
      agreementDate,
      dueDate,
    });

    const submissionId = Array.isArray(result) ? result[0]?.submission_id ?? result[0]?.id : result?.id;
    console.log(`Order ${order.name}: layby agreement sent for signature (submission id ${submissionId}).`);
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

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer_email: customerEmail,
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
      success_url: `${STOREFRONT_BASE_URL}/pages/how-layby-works?layby_paid=1`,
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
      product_reference: orderReference,
      full_price: fullPriceStr,
      deposit_amount: depositAmountStr,
      customer_name: customerName,
      customer_phone: customerPhone,
    } = session.metadata;

    const fullPrice = parseFloat(fullPriceStr);
    const depositAmount = parseFloat(depositAmountStr);
    const currency = session.currency.toUpperCase();
    const customerEmail = session.customer_details?.email || session.customer_email;

    // Reserve the real item immediately, before sending the agreement — same
    // reasoning as the original order-webhook flow above: protect the item
    // the instant payment clears, regardless of what happens next.
    await reserveTargetProduct(productGid);

    if (!DOCUSEAL_API_KEY || !DOCUSEAL_TEMPLATE_ID) {
      console.warn(
        `Stripe checkout ${session.id}: deposit paid, ${itemTitle} reserved. DocuSeal not configured — agreement NOT sent. Send it manually, then add the DocuSeal env vars to automate this step too.`
      );
      return;
    }

    const agreementDate = new Date();
    const dueDate = new Date(agreementDate);
    dueDate.setDate(dueDate.getDate() + parseInt(LAYBY_TERM_WEEKS, 10) * 7);

    const result = await sendForSignature({
      customerName: customerName || "Customer",
      customerEmail,
      customerPhone,
      itemTitle,
      orderReference,
      totalPrice: fullPrice,
      depositAmount,
      currency,
      agreementDate,
      dueDate,
    });

    // DocuSeal's response is an array, one entry per submitter — we only
    // ever send one (the customer), so [0] is the submission we just made.
    const submissionId = Array.isArray(result) ? result[0]?.submission_id ?? result[0]?.id : result?.id;
    console.log(
      `Stripe checkout ${session.id}: deposit paid, ${itemTitle} reserved, agreement sent (submission id ${submissionId}).`
    );
  } catch (err) {
    console.error("Error processing Stripe checkout.session.completed:", err);
  }
}

app.get("/healthz", (_req, res) => res.status(200).send("ok"));

app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
