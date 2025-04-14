<script lang="ts">
    import { RowCellDefinition } from "../table";

    export let title: string;
    export let tableNumber: number;

    export let headers: string[];
    export let rowCellDefinitions: RowCellDefinition[][];
</script>

<div class="w-full overflow-x-auto">
    <table class="border-collapse table-fixed sm:table-auto w-full text-sm">
        <caption class="caption-bottom">
            Table {tableNumber}: {title}
        </caption>
        <thead class="bg-openid">
            <tr>
                {#each headers as header}
                    <th class="break-words border font-medium text-lg p-4 pl-8 pt-3 pb-3 text-left"
                        >{header}</th
                    >
                {/each}
            </tr>
        </thead>
        <tbody class="bg-white">
            {#each rowCellDefinitions as rowCellDefinition}
                <tr>
                    {#each rowCellDefinition as rowCell}
                        {#if rowCell.Link !== undefined}
                        <td class="break-words border border-slate-200 p-4 pl-8">
                            <a href="{rowCell.Link}" class="underline decoration-2 hover:decoration-openid">{rowCell.Data}</a>
                        </td>
                        {:else}
                            <td class="break-words border border-slate-200 p-4 pl-8">{rowCell.Data}</td>
                        {/if}                        
                    {/each}
                </tr>
            {/each}
        </tbody>
    </table>
</div>