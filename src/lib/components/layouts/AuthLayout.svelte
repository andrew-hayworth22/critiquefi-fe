<script>
	const { title, children } = $props();
</script>

<div class="sm:mx-auto sm:w-full sm:max-w-sm">
	{#if title}
	<h2 class="mt-10 text-center text-2xl/9 font-bold tracking-tight text-gray-900 dark:text-white">
		{@render title()}
	</h2>
	{/if}

	{@render children?.()}
</div>
