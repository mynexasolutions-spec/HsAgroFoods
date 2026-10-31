import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'
import { revalidatePath } from 'next/cache'
import { createAdminClient } from '@/lib/supabase/admin'
import { markOrderPaid, markOrderFailed, expectedAmountPaise } from '@/lib/orderPayment'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

function isValidSignature(rawBody: string, signature: string, secret: string) {
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex')
  const a = Buffer.from(signature, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

function refreshOrderPages() {
  revalidatePath('/admin/orders')
  revalidatePath('/account/orders')
  revalidatePath('/shop')
  revalidatePath('/admin/products')
}

export async function POST(req: NextRequest) {
  try {
    // The signature is computed over the exact raw body, so read it as text
    const rawBody = await req.text()
    const signature = req.headers.get('x-razorpay-signature')
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET?.trim()

    if (!webhookSecret) {
      console.error('[Razorpay Webhook] RAZORPAY_WEBHOOK_SECRET is not configured.')
      return NextResponse.json({ error: 'Webhook is not configured' }, { status: 500 })
    }

    if (!signature) {
      return NextResponse.json({ error: 'Missing signature' }, { status: 400 })
    }

    if (!isValidSignature(rawBody, signature, webhookSecret)) {
      console.error('[Razorpay Webhook] Invalid signature.')
      return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
    }

    const { event, payload } = JSON.parse(rawBody)
    const admin = createAdminClient()

    switch (event) {
      case 'payment.captured':
      case 'order.paid': {
        const payment = payload?.payment?.entity
        const rzpOrderId: string | undefined = payment?.order_id || payload?.order?.entity?.id

        if (!payment?.id || !rzpOrderId) {
          return NextResponse.json({ received: true, note: 'No payment found' })
        }

        const { data: order, error } = await admin
          .from('orders')
          .select('id, order_number, total_amount, payment_status')
          .eq('razorpay_order_id', rzpOrderId)
          .maybeSingle()

        if (error) {
          console.error('[Razorpay Webhook] Order lookup failed:', error.message)
          return NextResponse.json({ error: 'Lookup failed' }, { status: 500 }) // Razorpay retries
        }

        if (!order) {
          // Unknown order: acknowledge so Razorpay does not retry forever
          console.error(`[Razorpay Webhook] No order for Razorpay order ${rzpOrderId}`)
          return NextResponse.json({ received: true, note: 'Order not found' })
        }

        // Never trust the event for a different amount/currency than we charged
        if (
          Number(payment.amount) !== expectedAmountPaise(order.total_amount) ||
          (payment.currency && payment.currency !== 'INR')
        ) {
          console.error(`[Razorpay Webhook] Amount mismatch for order #${order.order_number}`)
          return NextResponse.json({ received: true, note: 'Amount mismatch' })
        }

        if (payment.status && payment.status !== 'captured') {
          return NextResponse.json({ received: true, note: 'Payment not captured' })
        }

        const result = await markOrderPaid(admin, order.id, payment.id)
        if (result.error) {
          console.error('[Razorpay Webhook] markOrderPaid failed:', result.error)
          return NextResponse.json({ error: 'Database update failed' }, { status: 500 }) // retry
        }

        // Visible in Vercel > Logs, so you can see the webhook doing its job
        console.log(`[Razorpay Webhook] ${event}: order #${order.order_number} ${result.applied ? 'marked PAID by webhook' : 'was already paid (browser verify or the other webhook event got there first)'}`)
        if (result.applied) refreshOrderPages()
        return NextResponse.json({ received: true, applied: result.applied })
      }

      case 'payment.failed': {
        const payment = payload?.payment?.entity
        if (payment?.order_id) {
          const { data: order } = await admin
            .from('orders')
            .select('id')
            .eq('razorpay_order_id', payment.order_id)
            .maybeSingle()

          if (order) {
            const { error } = await markOrderFailed(admin, order.id)
            if (error) {
              console.error('[Razorpay Webhook] markOrderFailed failed:', error)
              return NextResponse.json({ error: 'Database update failed' }, { status: 500 })
            }
            console.log(`[Razorpay Webhook] payment.failed: Razorpay order ${payment.order_id} marked failed`)
            refreshOrderPages()
          }
        }
        return NextResponse.json({ received: true })
      }

      default:
        return NextResponse.json({ received: true, ignored: true })
    }
  } catch (error) {
    console.error('[Razorpay Webhook] Unexpected error:', error)
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
