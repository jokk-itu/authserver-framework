export class RowCellDefinition {
    Data: string;
    Link?: string;
    
    constructor(data: string, link?: string) {
        this.Data = data;
        this.Link = link;
    }
}