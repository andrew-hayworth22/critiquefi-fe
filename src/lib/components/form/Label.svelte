<script lang="ts">
	let { input, children, ...props} = $props();
</script>

<label for="{input}"
			 class="block text-sm/6 font-medium text-gray-900 dark:text-gray-100"
			 {...props}
>
	{@render children()}
</label>