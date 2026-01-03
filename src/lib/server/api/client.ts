import { API_URL } from '$env/static/private';
import { error, type RequestEvent } from '@sveltejs/kit';

type ApiFetchOptions = {
	method?: string;
	headers?: Record<string, string>;
	body?: never;
};

function setAuthCookies(
	event: RequestEvent,
	tokens: { accessToken: string; refreshToken: string }
) {
	// Access token (short-lived)
	event.cookies.set('access_token', tokens.accessToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
	});

	// Refresh token (longer-lived, rotates)
	event.cookies.set('refresh_token', tokens.refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
		// maxAge: 60 * 60 * 24 * 30,
	});
}

async function refreshTokens(event: RequestEvent) {
	const refresh = event.cookies.get('refresh_token');
	if (!refresh) throw error(401, 'Not authenticated');

	const res = await fetch(`${API_URL}/auth/refresh`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ refreshToken: refresh })
	});

	if (!res.ok) {
		event.cookies.delete('access_token', { path: '/' });
		event.cookies.delete('refresh_token', { path: '/' });
		throw error(401, 'Session expired');
	}

	const tokens = await res.json(); // { accessToken, refreshToken }
	setAuthCookies(event, tokens);
	return tokens.accessToken;
}

const refreshInFlight = new Map<string, Promise<string>>();
async function refreshWithMutex(event: RequestEvent) {
	const key = event.cookies.get('refresh_token') ?? 'no-refresh';
	if (refreshInFlight.has(key)) return refreshInFlight.get(key)!;

	const p = refreshTokens(event).finally(() => refreshInFlight.delete(key));
	refreshInFlight.set(key, p);
	return p;
}

export async function apiFetch(event: RequestEvent, path: string, options: ApiFetchOptions) {
	const accessToken = event.cookies.get('access_token');

	const makeReq = (access?: string) =>
		fetch(`${API_URL}${path}`, {
			method: options.method ?? 'GET',
			headers: {
				...(options.headers ?? {}),
				...(accessToken ? { authorization: `Bearer ${access}` } : {}),
				...(options.body ? { 'content-type': 'application/json' } : {})
			},
			body: options.body ? JSON.stringify(options.body) : undefined
		});

	let res = await makeReq(accessToken);

	if (res.status === 401) {
		const newAccessToken = await refreshWithMutex(event);
		res = await makeReq(newAccessToken);
	}

	return res;
}