<script lang="ts">
    export let title: string;
    export let tableNumber: number;

    export let headers: string[];
    export let rows: string[][];
</script>

<div class="w-full overflow-x-auto">
    <table class="border-collapse table-fixed sm:table-auto w-full text-sm">
        <caption class="caption-bottom">
            Table {tableNumber}: {title}
        </caption>
        <thead class="bg-openid">
            <tr>
                {#each headers as header}
                    <th class="border font-medium text-lg p-4 pl-8 pt-3 pb-3 text-left"
                        >{header}</th
                    >
                {/each}
            </tr>
        </thead>
        <tbody class="bg-white">
            {#each rows as row}
                <tr>
                    {#each row as rowData}
                        <td class="break-words border border-slate-200 p-4 pl-8">{rowData}</td>
                    {/each}
                </tr>
            {/each}
        </tbody>
    </table>
</div>