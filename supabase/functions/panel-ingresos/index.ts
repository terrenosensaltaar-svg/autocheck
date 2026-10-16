import { createClient } from "npm:@supabase/supabase-js@2";

const allowedOrigins = new Set([
  "https://autochecksalta.com.ar",
  "https://www.autochecksalta.com.ar",
]);
const encoder = new TextEncoder();
const allowedStatuses = new Set([
  "Recibido",
  "En diagnóstico",
  "Esperando aprobación",
  "Esperando repuestos",
  "En reparación",
  "Listo para retirar",
  "Entregado",
  "Cancelado",
]);

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "Content-Type": "application/json" },
  });
}

function corsHeaders(request: Request) {
  const origin = request.headers.get("origin") ?? "";
  if (!allowedOrigins.has(origin)) return null;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) return new Uint8Array();
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (byte) => parseInt(byte, 16));
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length || left.length === 0) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

async function passwordHash(password: string, salt: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(salt), iterations: 200_000, hash: "SHA-256" },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function getAdmin(username: string, password: string) {
  const { data: admin } = await supabase
    .from("panel_admins")
    .select("username,password_salt,password_hash,must_change_password,failed_attempts,locked_until")
    .eq("username", username)
    .maybeSingle();
  if (!admin) return { admin: null, valid: false, locked: false };
  if (admin.locked_until && Date.parse(admin.locked_until) > Date.now()) {
    return { admin, valid: false, locked: true };
  }
  const salt = admin?.password_salt ?? "00000000000000000000000000000000";
  const expected = admin?.password_hash ?? "0000000000000000000000000000000000000000000000000000000000000000";
  const valid = constantTimeEqual(await passwordHash(password, salt), fromHex(expected));
  return { admin, valid, locked: false };
}

Deno.serve(async (request: Request) => {
  const cors = corsHeaders(request);
  if (!cors) return json({ error: "Origen no autorizado." }, 403);
  if (request.method === "OPTIONS") return new Response("ok", { headers: cors });
  const respond = (data: unknown, status = 200) => json(data, status, cors);
  if (request.method !== "POST") return respond({ error: "Método no permitido." }, 405);

  try {
    const body = await request.json();
    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const action = typeof body.action === "string" ? body.action : "";
    if (!username || !password || username.length > 40 || password.length > 256) {
      return respond({ error: "Usuario o contraseña incorrectos." }, 401);
    }

    const auth = await getAdmin(username, password);
    if (auth.locked) return respond({ error: "Se bloqueó el acceso por intentos fallidos. Esperá 15 minutos e intentá nuevamente." }, 429);
    if (!auth.valid || !auth.admin) {
      if (auth.admin) {
        const { data: locked, error: rateError } = await supabase.rpc("registrar_fallo_login_panel", { p_username: username });
        if (rateError) throw rateError;
        if (locked) return respond({ error: "Se bloqueó el acceso por intentos fallidos. Esperá 15 minutos e intentá nuevamente." }, 429);
      }
      return respond({ error: "Usuario o contraseña incorrectos." }, 401);
    }
    const admin = auth.admin;
    const { error: resetError } = await supabase.from("panel_admins").update({ failed_attempts: 0, locked_until: null }).eq("username", username);
    if (resetError) throw resetError;

    if (admin.must_change_password && action !== "change_password") {
      return respond({ ok: true, mustChangePassword: true });
    }

    if (action === "login") return respond({ ok: true, mustChangePassword: false });

    if (action === "change_password") {
      const nextPassword = typeof body.new_password === "string" ? body.new_password : "";
      if (nextPassword.length < 16 || nextPassword.length > 256) {
        return respond({ error: "La nueva contraseña debe tener al menos 16 caracteres." }, 400);
      }
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const salt = Array.from(saltBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
      const hash = await passwordHash(nextPassword, salt);
      const hashHex = Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
      const { error } = await supabase.from("panel_admins").update({
        password_salt: salt,
        password_hash: hashHex,
        must_change_password: false,
      }).eq("username", username);
      if (error) throw error;
      return respond({ ok: true });
    }

    if (action === "list") {
      const { data, error } = await supabase
        .from("ingresos_vehiculos")
        .select("id,cliente_nombre,cliente_telefono,vehiculo_marca,vehiculo_modelo,vehiculo_patente,combustible,estado_arranque,motivo,modo_llegada,fecha_turno,franja_turno,firma_data_url,consentimiento,fecha_hora_firma,created_at,estado_reparacion,notas_taller,updated_at")
        .order("created_at", { ascending: false })
        .limit(500);
      if (error) throw error;
      return respond({ data });
    }

    if (action === "update") {
      const id = typeof body.id === "string" ? body.id : "";
      const status = typeof body.estado_reparacion === "string" ? body.estado_reparacion : "";
      const notes = typeof body.notas_taller === "string" ? body.notas_taller : "";
      if (!/^[0-9a-f-]{36}$/i.test(id) || !allowedStatuses.has(status) || notes.length > 5000) {
        return respond({ error: "Los datos de actualización no son válidos." }, 400);
      }
      const { error } = await supabase.from("ingresos_vehiculos").update({
        estado_reparacion: status,
        notas_taller: notes,
        updated_at: new Date().toISOString(),
      }).eq("id", id);
      if (error) throw error;
      return respond({ ok: true });
    }

    return respond({ error: "Acción no válida." }, 400);
  } catch (error) {
    console.error("Error en panel-ingresos:", error);
    return respond({ error: "No se pudo completar la operación. Intentá nuevamente." }, 500);
  }
});
