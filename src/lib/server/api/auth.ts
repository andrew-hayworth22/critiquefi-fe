import  { error, type RequestEvent } from '@sveltejs/kit';
import { API_URL } from '$env/static/private';
import { getTokens, setAuthCookies } from './client';

type RegisterRequest = {
	email: string,
	display_name: string,
	name: string,
	password: string,
	confirm_password: string,
	remember: boolean
}

export async function register(event: RequestEvent) {
	const formData = await event.request.formData();
	const req: RegisterRequest = {
		email: formData.get('email')?.toString() ?? '',
		display_name: formData.get('display_name')?.toString() ?? '',
		name: formData.get('name')?.toString() ?? '',
		password: formData.get('password')?.toString() ?? '',
		confirm_password: formData.get('confirm_password')?.toString() ?? '',
		remember: formData.get('remember')?.toString() === 'on'
	}

	const res = await fetch(`${API_URL}/auth/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(req)
	})

	if(res.status === 401) throw error(401, 'Registration failed')

	const tokens = await getTokens(res);
	setAuthCookies(event, tokens);
}