import { API_URL, ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME } from '$env/static/private';
import { error, type RequestEvent } from '@sveltejs/kit';

// Defines a request to the external API
export type ApiFetchOptions = {
	method?: string;
	headers?: Record<string, string>;
	body?: never;
};

// Defines the authentication tokens from external API
export type ApiTokens = {
	accessToken: string,
	refreshToken: string | null
};

// apiFetch makes a request to the external API, refreshing the access token if necessary
export async function apiFetch(event: RequestEvent, path: string, options: ApiFetchOptions) {
	const accessToken = event.cookies.get(ACCESS_COOKIE_NAME);

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

// getTokens returns the refresh token from the response headers and the access token from the response body
export async function getTokens(response: Response): Promise<ApiTokens> {
	const json = await response.json(); // { accessToken }

	const accessToken: string = json?.access_token;
	const refreshToken = response.headers.get('set-cookie');

	return {
		accessToken,
		refreshToken
	}
}

// setAuthCookies sets the access and refresh tokens in the browser's cookies
export function setAuthCookies(
	event: RequestEvent,
	tokens: ApiTokens
) {
	// Access token (short-lived)
	event.cookies.set(ACCESS_COOKIE_NAME, tokens.accessToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
	});

	// Refresh token (longer-lived, rotates)
	event.cookies.set(REFRESH_COOKIE_NAME, tokens.refreshToken ?? '', {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production'
		// maxAge: 60 * 60 * 24 * 30,
	});
}

// activeRefreshes keeps track of active refresh promises to prevent multiple concurrent refreshes
const activeRefreshes = new Map<string, Promise<string>>();
// refreshWithMutex ensures that only one refresh is in progress at a time
async function refreshWithMutex(event: RequestEvent) {
	const key = event.cookies.get('refresh_token') ?? 'no-refresh';
	if (activeRefreshes.has(key)) return activeRefreshes.get(key)!;

	const p = refreshTokens(event).finally(() => activeRefreshes.delete(key));
	activeRefreshes.set(key, p);
	return p;
}

// refreshTokens attempts to refresh the access token using the refresh token
async function refreshTokens(event: RequestEvent) {
	const refresh = event.cookies.get('refresh_token');
	if (!refresh) throw error(401, 'Not authenticated');

	const res = await fetch(`${API_URL}/auth/refresh`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
	});

	if (!res.ok) {
		event.cookies.delete(ACCESS_COOKIE_NAME, { path: '/' });
		event.cookies.delete(REFRESH_COOKIE_NAME, { path: '/' });
		throw error(401, 'Session expired');
	}

	const tokens = await getTokens(res);
	setAuthCookies(event, tokens);

	return tokens.accessToken;
}


