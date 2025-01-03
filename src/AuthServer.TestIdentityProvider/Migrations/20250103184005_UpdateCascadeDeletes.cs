using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthServer.TestIdentityProvider.Migrations
{
    /// <inheritdoc />
    public partial class UpdateCascadeDeletes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuthorizationCode_AuthorizationGrant_AuthorizationGrantId",
                table: "AuthorizationCode");

            migrationBuilder.DropForeignKey(
                name: "FK_AuthorizeMessage_Client_ClientId",
                table: "AuthorizeMessage");

            migrationBuilder.DropForeignKey(
                name: "FK_Contact_Client_ClientId",
                table: "Contact");

            migrationBuilder.DropForeignKey(
                name: "FK_Nonce_AuthorizationGrant_AuthorizationGrantId",
                table: "Nonce");

            migrationBuilder.DropForeignKey(
                name: "FK_PostLogoutRedirectUri_Client_ClientId",
                table: "PostLogoutRedirectUri");

            migrationBuilder.DropForeignKey(
                name: "FK_RedirectUri_Client_ClientId",
                table: "RedirectUri");

            migrationBuilder.DropForeignKey(
                name: "FK_RequestUri_Client_ClientId",
                table: "RequestUri");

            migrationBuilder.AddForeignKey(
                name: "FK_AuthorizationCode_AuthorizationGrant_AuthorizationGrantId",
                table: "AuthorizationCode",
                column: "AuthorizationGrantId",
                principalTable: "AuthorizationGrant",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_AuthorizeMessage_Client_ClientId",
                table: "AuthorizeMessage",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Contact_Client_ClientId",
                table: "Contact",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Nonce_AuthorizationGrant_AuthorizationGrantId",
                table: "Nonce",
                column: "AuthorizationGrantId",
                principalTable: "AuthorizationGrant",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_PostLogoutRedirectUri_Client_ClientId",
                table: "PostLogoutRedirectUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RedirectUri_Client_ClientId",
                table: "RedirectUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RequestUri_Client_ClientId",
                table: "RequestUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_AuthorizationCode_AuthorizationGrant_AuthorizationGrantId",
                table: "AuthorizationCode");

            migrationBuilder.DropForeignKey(
                name: "FK_AuthorizeMessage_Client_ClientId",
                table: "AuthorizeMessage");

            migrationBuilder.DropForeignKey(
                name: "FK_Contact_Client_ClientId",
                table: "Contact");

            migrationBuilder.DropForeignKey(
                name: "FK_Nonce_AuthorizationGrant_AuthorizationGrantId",
                table: "Nonce");

            migrationBuilder.DropForeignKey(
                name: "FK_PostLogoutRedirectUri_Client_ClientId",
                table: "PostLogoutRedirectUri");

            migrationBuilder.DropForeignKey(
                name: "FK_RedirectUri_Client_ClientId",
                table: "RedirectUri");

            migrationBuilder.DropForeignKey(
                name: "FK_RequestUri_Client_ClientId",
                table: "RequestUri");

            migrationBuilder.AddForeignKey(
                name: "FK_AuthorizationCode_AuthorizationGrant_AuthorizationGrantId",
                table: "AuthorizationCode",
                column: "AuthorizationGrantId",
                principalTable: "AuthorizationGrant",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_AuthorizeMessage_Client_ClientId",
                table: "AuthorizeMessage",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Contact_Client_ClientId",
                table: "Contact",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Nonce_AuthorizationGrant_AuthorizationGrantId",
                table: "Nonce",
                column: "AuthorizationGrantId",
                principalTable: "AuthorizationGrant",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_PostLogoutRedirectUri_Client_ClientId",
                table: "PostLogoutRedirectUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_RedirectUri_Client_ClientId",
                table: "RedirectUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_RequestUri_Client_ClientId",
                table: "RequestUri",
                column: "ClientId",
                principalTable: "Client",
                principalColumn: "Id");
        }
    }
}
