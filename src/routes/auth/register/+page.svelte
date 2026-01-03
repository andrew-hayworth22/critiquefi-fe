<script lang="ts">
	import { enhance } from '$app/forms';
	import AuthLayout from '$lib/components/layouts/AuthLayout.svelte';
	import Label from '$lib/components/form/Label.svelte';
	import Input from '$lib/components/form/Input.svelte';
	import ButtonPrimary from '$lib/components/form/ButtonPrimary.svelte';
</script>

<svelte:head>
	<title>Register</title>
</svelte:head>

<AuthLayout>
	{#snippet title()}Register{/snippet}

	<form method="POST" class="space-y-6" use:enhance>
		<div>
			<Label input="email">Email</Label>
			<div class="mt-2">
				<Input id="email" type="email" required autocomplete="email" />
			</div>
		</div>

		<div>
			<Label input="name">Name</Label>
			<div class="mt-2">
				<Input id="name" type="text" required autocomplete="name"/>
			</div>
		</div>

		<div>
			<Label input="display_name">Display Name</Label>
			<div class="mt-2">
				<Input id="display_name" type="text" required autocomplete="username"/>
			</div>
		</div>

		<div>
			<Label input="password">Password</Label>
			<div class="mt-2">
				<Input id="password" type="password" required autocomplete="current-password" />
			</div>
		</div>

		<div>
			<Label input="confirm_password">Confirm Password</Label>
			<div class="mt-2">
				<Input id="confirm_password" type="password" required />
			</div>
		</div>

		<div>
			<ButtonPrimary type="submit" extendedClass="w-full">Register</ButtonPrimary>
		</div>
	</form>

	<p class="mt-10 text-center text-sm/6 text-gray-500 dark:text-gray-400">
		Already registered?
		<a href="/auth/login" class="font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300">Login</a>
	</p>
</AuthLayout>

