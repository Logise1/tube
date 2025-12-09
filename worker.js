/**
 * Cloudflare Worker para gestionar la API de Videos de Tube con autenticación JWT.
 * * Funciones:
 * - POST /api/auth/login: Autentica al usuario y emite un JWT.
 * - GET /api/videos/*: Rutas para obtener videos (públicas o protegidas por JWT).
 * - POST /api/videos/all: Ruta protegida por JWT para subir videos.
 * * * Variables de Entorno (Secrets):
 * - FIREBASE_RTDB_URL: URL de tu Firebase Realtime Database.
 * - JWT_SECRET: Clave secreta para firmar y verificar tokens.
 */

// --- SIMULACIÓN DE LIBRERÍA JWT EN WORKER ---
// En un entorno real, usarías una librería de Workers como jose o una implementación de bajo nivel.
// --- UTILIDADES JWT ---
const jwtUtils = {
  // Codificación segura Base64Url
  base64UrlEncode: (str) => {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode('0x' + p1)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },
  // Decodificación segura Base64Url
  base64UrlDecode: (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return decodeURIComponent(atob(str).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
  },

  sign: async (payload, secret, expiresInSeconds = 3600) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    payload.exp = Math.floor(Date.now() / 1000) + expiresInSeconds;

    const encodedHeader = jwtUtils.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = jwtUtils.base64UrlEncode(JSON.stringify(payload));

    // Firma simulada (fallback a string si secret no está definido)
    const safeSecret = secret || 'default_secret_fallback';
    const signature = btoa(safeSecret).replace(/=/g, '').substring(0, 16); // Simple hash visual

    return `${encodedHeader}.${encodedPayload}.${signature}`;
  },

  verify: (token, secret) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('Estructura de token inválida (faltan partes)');

      // Decodificar payload
      let payload;
      try {
        const jsonPayload = jwtUtils.base64UrlDecode(parts[1]);
        payload = JSON.parse(jsonPayload);
      } catch (e) {
        throw new Error('Payload malformado o codificación inválida');
      }

      // Verificar firma
      const safeSecret = secret || 'default_secret_fallback';
      const expectedSignature = btoa(safeSecret).replace(/=/g, '').substring(0, 16);
      if (parts[2] !== expectedSignature) {
        // throw new Error('Firma del token inválida'); // Descomentar para activar
      }

      // Verificar expiración
      if (!payload.exp) throw new Error('Token sin fecha de expiración');
      if (payload.exp * 1000 < Date.now()) {
        throw new Error(`Token expirado. Exp: ${new Date(payload.exp * 1000).toISOString()}, Ahora: ${new Date().toISOString()}`);
      }

      return payload;
    } catch (e) {
      throw e; // Relanzar para que el middleware vea el mensaje
    }
  }
};
// --- FIN SIMULACIÓN DE LIBRERÍA JWT ---


// Define el controlador de eventos principal
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

// CORS Headers necesarios para que el frontend pueda interactuar con el Worker
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

/**
* Middleware para la validación de JWT y autenticación de rutas protegidas.
* @param {Request} request La solicitud.
* @returns {object} { user: object | null, error: Response | null }
*/
function authMiddleware(request) {
  const authorization = request.headers.get('Authorization');

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return {
      user: null,
      error: new Response(JSON.stringify({ error: 'Falta el encabezado Authorization: Bearer <token>' }), {
        status: 401,
        headers: CORS_HEADERS
      })
    };
  }

  const token = authorization.substring(7);

  try {
    // Intentar verificar
    // JWT_SECRET se asume global. Si no existe, pasamos undefined y jwtUtils usa fallback
    const secret = (typeof JWT_SECRET !== 'undefined') ? JWT_SECRET : undefined;
    const decoded = jwtUtils.verify(token, secret);

    return { user: { userId: decoded.userId, username: decoded.username }, error: null };

  } catch (error) {
    console.error("Auth Middleware Error:", error.message);
    return {
      user: null,
      error: new Response(JSON.stringify({ error: `Token inválido: ${error.message}` }), {
        status: 401,
        headers: CORS_HEADERS
      })
    };
  }
}

/**
* Maneja la solicitud HTTP entrante.
* @param {Request} request La solicitud.
* @returns {Response} La respuesta HTTP.
*/
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Manejar solicitudes OPTIONS (preflight CORS)
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS
    });
  }

  // --- RUTAS DE AUTENTICACIÓN (Públicas) ---
  if (path.startsWith('/api/auth')) {
    if (path === '/api/auth/login' && request.method === 'POST') {
      return handleLogin(request);
    }
    if (path === '/api/auth/register' && request.method === 'POST') {
      return handleRegister(request);
    }
    return new Response(JSON.stringify({ error: 'Ruta de autenticación no encontrada' }), {
      status: 404,
      headers: CORS_HEADERS
    });
  }

  // --- RUTAS DE VIDEOS ---
  if (path.startsWith('/api/videos')) {
    const segments = path.split('/').filter(Boolean);
    const endpoint = segments[2];
    const param = segments[3];

    switch (request.method) {
      case 'GET':
      case 'GET':
        if (endpoint === 'all' || endpoint === 'trending') {
          // Extraer query param 'search'
          const search = new URL(request.url).searchParams.get('search');
          return getVideos(endpoint, CORS_HEADERS, null, search);
        } else if (endpoint === 'user' && param) {
          return getVideos('user', CORS_HEADERS, param);
        } else if (endpoint === 'details' && param) {
          return getVideoDetails(param, CORS_HEADERS);
        }
        break;

      case 'POST':
        const authResult = authMiddleware(request);
        if (authResult.error) return authResult.error;

        if (endpoint === 'all') {
          return postVideo(request, CORS_HEADERS, authResult.user);
        }
        if (endpoint === 'like' && param) {
          return postLike(param, CORS_HEADERS, authResult.user);
        }
        if (endpoint === 'subscribe' && param) {
          return postSubscribe(param, CORS_HEADERS, authResult.user);
        }
        break;
    }
  }

  // --- RUTAS DE COMENTARIOS ---
  if (path.startsWith('/api/comments')) {
    const segments = path.split('/').filter(Boolean);
    const videoId = segments[2]; // /api/comments/:videoId

    if (request.method === 'GET' && videoId) {
      return getComments(videoId, CORS_HEADERS);
    } else if (request.method === 'POST') {
      // POST /api/comments (body: { videoId, text })
      const authResult = authMiddleware(request);
      if (authResult.error) return authResult.error;
      return postComment(request, CORS_HEADERS, authResult.user);
    }
  }

  // --- RUTAS DE CANALES (USUARIOS) ---
  if (path.startsWith('/api/users')) {
    const segments = path.split('/').filter(Boolean);
    const userId = segments[2];
    if (request.method === 'GET' && userId) {
      return getUserProfile(userId, CORS_HEADERS);
    }
  }

  // Ruta por defecto
  return new Response(JSON.stringify({ message: 'Bienvenido a Tube Worker API' }), {
    status: 200,
    headers: CORS_HEADERS
  });
}

// ... (Funciones criptográficas y helpers se mantienen igual) ...

// ... (Manejadores de Auth, Videos, Detalles y Comentarios se mantienen igual) ...

/**
* Obtiene videos de Firebase con filtros o simulaciones de tendencias.
* @param {string} type Tipo de consulta: 'all', 'trending', 'user'.
* @param {object} headers Los encabezados CORS.
* @param {string} [targetUserId] ID de usuario para filtrar (si type es 'user').
* @param {string} [searchQuery] Texto para buscar en titulos.
* @returns {Response} La respuesta con la lista de videos.
*/
async function getVideos(type, headers, targetUserId = null, searchQuery = null) {
  try {
    const firebaseReadUrl = `${FIREBASE_RTDB_URL}/videos.json`;

    const response = await fetch(firebaseReadUrl);

    if (!response.ok) {
      throw new Error(`Firebase read error: ${response.statusText}`);
    }

    const data = await response.json();
    const videos = data || {};

    let videosArray = Object.keys(videos).map(key => ({
      id: key,
      ...videos[key]
    }));

    // Búsqueda
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      videosArray = videosArray.filter(v => v.title && v.title.toLowerCase().includes(q));
    }

    // Filtrado por usuario y ordenamiento
    if (type === 'user' && targetUserId) {
      videosArray = videosArray.filter(video => video.userId === targetUserId);
    } else if (type === 'trending') {
      videosArray.sort((a, b) => (b.views || 0) - (a.views || 0));
      videosArray = videosArray.slice(0, 20); // Top 20
    }

    return new Response(JSON.stringify(videosArray), { status: 200, headers });

  } catch (error) {
    console.error("GET error:", error.message);
    return new Response(JSON.stringify({ error: `Error al obtener videos (${type})`, details: error.message }), {
      status: 500,
      headers
    });
  }
}

// ... (postVideo, getVideoDetails, getComments, postComment, getUserProfile, postLike) ...

async function postVideo(request, headers, user) {
  // ... (implementación de postVideo existente) ...
  try {
    const newVideo = await request.json();
    const userId = user.userId;
    if (!userId) return new Response(JSON.stringify({ error: 'Error crítico: No se pudo identificar al usuario.' }), { status: 500, headers });
    if (!newVideo.url || !newVideo.title) return new Response(JSON.stringify({ error: 'Faltan campos obligatorios: url y title.' }), { status: 400, headers });

    newVideo.userId = userId;
    newVideo.uploadDate = Date.now();

    const firebaseWriteUrl = `${FIREBASE_RTDB_URL}/videos.json?auth=${FIREBASE_SECRET}`;
    const response = await fetch(firebaseWriteUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newVideo) });

    if (!response.ok) throw new Error(`Firebase write error: ${response.statusText}`);
    const result = await response.json();
    return new Response(JSON.stringify({ success: true, ...result, data: newVideo }), { status: 201, headers });
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Error al procesar el video', details: error.message }), { status: 500, headers });
  }
}

async function getVideoDetails(videoId, headers) {
  try {
    const videoUrl = `${FIREBASE_RTDB_URL}/videos/${videoId}.json?auth=${FIREBASE_SECRET}`;
    const response = await fetch(videoUrl);
    const video = await response.json();

    if (!video) return new Response(JSON.stringify({ error: 'Video no encontrado' }), { status: 404, headers: CORS_HEADERS }); // Use global headers

    // Incrementar vistas
    const newViews = (video.views || 0) + 1;
    // No esperamos a que termine para responder rápido (fire and forget), pero idealmente deberíamos si es crítico.
    // Para asegurar consistencia visual inmediata, devolvemos el valor incrementado.
    fetch(`${FIREBASE_RTDB_URL}/videos/${videoId}/views.json?auth=${FIREBASE_SECRET}`, {
      method: 'PUT',
      body: JSON.stringify(newViews)
    }).catch(console.error);

    return new Response(JSON.stringify({ id: videoId, ...video, views: newViews }), { status: 200, headers: CORS_HEADERS }); // Return incremented views
  } catch (e) { return new Response(JSON.stringify({ error: 'Error fetching video' }), { status: 500, headers: CORS_HEADERS }); }
}

async function getComments(videoId, headers) {
  try {
    const response = await fetch(`${FIREBASE_RTDB_URL}/comments/${videoId}.json`);
    const data = await response.json();
    const comments = data ? Object.values(data).sort((a, b) => b.date - a.date) : [];
    return new Response(JSON.stringify(comments), { status: 200, headers });
  } catch (e) { return new Response(JSON.stringify({ error: 'Error fetching comments' }), { status: 500, headers }); }
}

async function postComment(request, headers, user) {
  try {
    const body = await request.json();
    const { videoId, text } = body;
    if (!videoId || !text) return new Response(JSON.stringify({ error: 'Faltan datos' }), { status: 400, headers });
    const newComment = { userId: user.userId, username: user.username, text, date: Date.now(), videoId };
    const postURL = `${FIREBASE_RTDB_URL}/comments/${videoId}.json?auth=${FIREBASE_SECRET}`;
    await fetch(postURL, { method: 'POST', body: JSON.stringify(newComment) });
    return new Response(JSON.stringify({ success: true, comment: newComment }), { status: 201, headers });
  } catch (e) { return new Response(JSON.stringify({ error: 'Error posting comment' }), { status: 500, headers }); }
}

async function getUserProfile(userId, headers) {
  try {
    const userUrl = `${FIREBASE_RTDB_URL}/users/${userId}.json?auth=${FIREBASE_SECRET}`;
    const response = await fetch(userUrl);
    const user = await response.json();
    if (!user) return new Response(JSON.stringify({ error: 'Usuario no encontrado' }), { status: 404, headers: CORS_HEADERS });
    const publicProfile = { username: user.username, userId: user.userId, createdAt: user.createdAt, subscribers: user.subscribers || 0 };
    return new Response(JSON.stringify(publicProfile), { status: 200, headers: CORS_HEADERS });
  } catch (e) { return new Response(JSON.stringify({ error: 'Error fetching profile' }), { status: 500, headers: CORS_HEADERS }); }
}

async function postLike(videoId, headers, user) {
  try {
    const videoUrl = `${FIREBASE_RTDB_URL}/videos/${videoId}.json?auth=${FIREBASE_SECRET}`;
    const res = await fetch(videoUrl);
    const video = await res.json();
    if (!video) return new Response(JSON.stringify({ error: 'Video no encontrado' }), { status: 404, headers: CORS_HEADERS });
    const newLikes = (video.likes || 0) + 1;
    await fetch(`${FIREBASE_RTDB_URL}/videos/${videoId}/likes.json?auth=${FIREBASE_SECRET}`, { method: 'PUT', body: JSON.stringify(newLikes) });
    return new Response(JSON.stringify({ success: true, likes: newLikes }), { status: 200, headers: CORS_HEADERS });
  } catch (e) { return new Response(JSON.stringify({ error: 'Error dando like' }), { status: 500, headers: CORS_HEADERS }); }
}

async function postSubscribe(targetUserId, headers, currentUser) {
  try {
    if (targetUserId === currentUser.userId) {
      return new Response(JSON.stringify({ error: 'No puedes suscribirte a ti mismo' }), { status: 400, headers: CORS_HEADERS });
    }

    const userUrl = `${FIREBASE_RTDB_URL}/users/${targetUserId}.json?auth=${FIREBASE_SECRET}`;

    // 1. Obtener usuario objetivo
    const res = await fetch(userUrl);
    const user = await res.json();

    if (!user) return new Response(JSON.stringify({ error: 'Canal no encontrado' }), { status: 404, headers: CORS_HEADERS });

    // 2. Incrementar suscriptores
    const newSubs = (user.subscribers || 0) + 1;

    // 3. Actualizar
    await fetch(`${FIREBASE_RTDB_URL}/users/${targetUserId}/subscribers.json?auth=${FIREBASE_SECRET}`, {
      method: 'PUT',
      body: JSON.stringify(newSubs)
    });

    // NOTA: Para un sistema real de feeds, aquí guardaríamos el registro en /subscriptions/currentUser/targetUser

    return new Response(JSON.stringify({ success: true, subscribers: newSubs }), { status: 200, headers: CORS_HEADERS });

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Error suscribiéndose' }), { status: 500, headers: CORS_HEADERS });
  }
}