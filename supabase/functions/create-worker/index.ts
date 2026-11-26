import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const svc = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    const token = (req.headers.get('Authorization') || '').replace(/^Bearer /i, '')
    const admin = createClient(url, svc, { auth: { persistSession: false } })

    const { data: u, error: ue } = await admin.auth.getUser(token)
    if (ue || !u?.user) return json({ error: 'غير مصرح' }, 401)
    const { data: prof } = await admin.from('profiles').select('role,is_active').eq('id', u.user.id).single()
    if (!prof || prof.role !== 'admin' || !prof.is_active) return json({ error: 'للمدير فقط' }, 403)

    const b = await req.json()
    const full_name = String(b.full_name || '').trim()
    const email = String(b.email || '').trim().toLowerCase()
    const password = String(b.password || '')
    const role = String(b.role || '')
    if (!['shop', 'workshop', 'buttons', 'delivery', 'admin'].includes(role)) return json({ error: 'القسم غير صحيح' }, 400)
    if (!full_name) return json({ error: 'اكتب اسم الموظف' }, 400)
    if (!/^\S+@\S+\.\S+$/.test(email)) return json({ error: 'البريد غير صحيح' }, 400)
    if (password.length < 8) return json({ error: 'كلمة السر لازم تكون 8 أحرف على الأقل' }, 400)

    const { data: c, error: ce } = await admin.auth.admin.createUser({
      email, password, email_confirm: true, user_metadata: { full_name },
    })
    if (ce || !c?.user) return json({ error: ce?.message || 'تعذر إنشاء الحساب' }, 400)
    const { error: pe } = await admin.from('profiles').update({ role, is_active: true, full_name }).eq('id', c.user.id)
    if (pe) return json({ error: 'تم إنشاء الحساب لكن تعذر ضبط القسم: ' + pe.message }, 500)
    return json({ ok: true, id: c.user.id })
  } catch (_e) {
    return json({ error: 'خطأ غير متوقع' }, 500)
  }
})
