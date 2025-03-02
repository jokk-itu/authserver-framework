using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace AuthServer.TestIdentityProvider.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuthenticationContextReference",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticationContextReference", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuthenticationMethodReference",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthenticationMethodReference", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Claim",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Claim", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "GrantType",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GrantType", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ResponseType",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ResponseType", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Scope",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scope", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SectorIdentifier",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Uri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    Salt = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SectorIdentifier", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SubjectIdentifier",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SubjectIdentifier", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Client",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    SecretHash = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    SecretExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    SecretExpiration = table.Column<int>(type: "int", nullable: true),
                    AccessTokenExpiration = table.Column<int>(type: "int", nullable: false),
                    RefreshTokenExpiration = table.Column<int>(type: "int", nullable: true),
                    AuthorizationCodeExpiration = table.Column<int>(type: "int", nullable: true),
                    RequestUriExpiration = table.Column<int>(type: "int", nullable: true),
                    JwksExpiration = table.Column<int>(type: "int", nullable: true),
                    TosUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    PolicyUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    ClientUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    LogoUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    InitiateLoginUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    BackchannelLogoutUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    JwksUri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    Jwks = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: true),
                    JwksExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RequireReferenceToken = table.Column<bool>(type: "bit", nullable: false),
                    RequireConsent = table.Column<bool>(type: "bit", nullable: false),
                    RequireSignedRequestObject = table.Column<bool>(type: "bit", nullable: false),
                    RequirePushedAuthorizationRequests = table.Column<bool>(type: "bit", nullable: false),
                    DefaultMaxAge = table.Column<int>(type: "int", nullable: true),
                    ApplicationType = table.Column<int>(type: "int", nullable: false),
                    TokenEndpointAuthMethod = table.Column<int>(type: "int", nullable: false),
                    SubjectType = table.Column<int>(type: "int", nullable: true),
                    TokenEndpointAuthEncryptionEnc = table.Column<int>(type: "int", nullable: true),
                    TokenEndpointAuthEncryptionAlg = table.Column<int>(type: "int", nullable: true),
                    TokenEndpointAuthSigningAlg = table.Column<int>(type: "int", nullable: true),
                    UserinfoEncryptedResponseEnc = table.Column<int>(type: "int", nullable: true),
                    UserinfoEncryptedResponseAlg = table.Column<int>(type: "int", nullable: true),
                    UserinfoSignedResponseAlg = table.Column<int>(type: "int", nullable: true),
                    RequestObjectEncryptionEnc = table.Column<int>(type: "int", nullable: true),
                    RequestObjectEncryptionAlg = table.Column<int>(type: "int", nullable: true),
                    RequestObjectSigningAlg = table.Column<int>(type: "int", nullable: true),
                    IdTokenEncryptedResponseEnc = table.Column<int>(type: "int", nullable: true),
                    IdTokenEncryptedResponseAlg = table.Column<int>(type: "int", nullable: true),
                    IdTokenSignedResponseAlg = table.Column<int>(type: "int", nullable: true),
                    SectorIdentifierId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Client", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Client_SectorIdentifier_SectorIdentifierId",
                        column: x => x.SectorIdentifierId,
                        principalTable: "SectorIdentifier",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Session",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    SubjectIdentifierId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Session", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Session_SubjectIdentifier_SubjectIdentifierId",
                        column: x => x.SubjectIdentifierId,
                        principalTable: "SubjectIdentifier",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "AuthorizeMessage",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reference = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", maxLength: 4096, nullable: false),
                    RedeemedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizeMessage", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizeMessage_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientAuthenticationContextReference",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    AuthenticationContextReferenceId = table.Column<int>(type: "int", nullable: false),
                    Order = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientAuthenticationContextReference", x => new { x.ClientId, x.AuthenticationContextReferenceId });
                    table.ForeignKey(
                        name: "FK_ClientAuthenticationContextReference_AuthenticationContextReference_AuthenticationContextReferenceId",
                        column: x => x.AuthenticationContextReferenceId,
                        principalTable: "AuthenticationContextReference",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_ClientAuthenticationContextReference_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "ClientGrantType",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    GrantTypeId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientGrantType", x => new { x.ClientId, x.GrantTypeId });
                    table.ForeignKey(
                        name: "FK_ClientGrantType_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ClientGrantType_GrantType_GrantTypeId",
                        column: x => x.GrantTypeId,
                        principalTable: "GrantType",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientResponseType",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ResponseTypeId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientResponseType", x => new { x.ClientId, x.ResponseTypeId });
                    table.ForeignKey(
                        name: "FK_ClientResponseType_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ClientResponseType_ResponseType_ResponseTypeId",
                        column: x => x.ResponseTypeId,
                        principalTable: "ResponseType",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ClientScope",
                columns: table => new
                {
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ScopeId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientScope", x => new { x.ClientId, x.ScopeId });
                    table.ForeignKey(
                        name: "FK_ClientScope_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ClientScope_Scope_ScopeId",
                        column: x => x.ScopeId,
                        principalTable: "Scope",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Consent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ConsentType = table.Column<int>(type: "int", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    SubjectIdentifierId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ClaimId = table.Column<int>(type: "int", nullable: true),
                    ScopeId = table.Column<int>(type: "int", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Consent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Consent_Claim_ClaimId",
                        column: x => x.ClaimId,
                        principalTable: "Claim",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Consent_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Consent_Scope_ScopeId",
                        column: x => x.ScopeId,
                        principalTable: "Scope",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Consent_SubjectIdentifier_SubjectIdentifierId",
                        column: x => x.SubjectIdentifierId,
                        principalTable: "SubjectIdentifier",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "Contact",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Email = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Contact", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Contact_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "PostLogoutRedirectUri",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Uri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PostLogoutRedirectUri", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PostLogoutRedirectUri_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RedirectUri",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Uri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RedirectUri", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RedirectUri_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RequestUri",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Uri = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RequestUri", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RequestUri_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationGrant",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    UpdatedAuthTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    CreatedAuthTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Subject = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    SessionId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    AuthenticationContextReferenceId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationGrant", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizationGrant_AuthenticationContextReference_AuthenticationContextReferenceId",
                        column: x => x.AuthenticationContextReferenceId,
                        principalTable: "AuthenticationContextReference",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_AuthorizationGrant_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_AuthorizationGrant_Session_SessionId",
                        column: x => x.SessionId,
                        principalTable: "Session",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationCode",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Value = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: false),
                    IssuedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RedeemedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    AuthorizationGrantId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCode", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizationCode_AuthorizationGrant_AuthorizationGrantId",
                        column: x => x.AuthorizationGrantId,
                        principalTable: "AuthorizationGrant",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationGrantAuthenticationMethodReference",
                columns: table => new
                {
                    AuthenticationMethodReferenceId = table.Column<int>(type: "int", nullable: false),
                    AuthorizationGrantId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationGrantAuthenticationMethodReference", x => new { x.AuthenticationMethodReferenceId, x.AuthorizationGrantId });
                    table.ForeignKey(
                        name: "FK_AuthorizationGrantAuthenticationMethodReference_AuthenticationMethodReference_AuthenticationMethodReferenceId",
                        column: x => x.AuthenticationMethodReferenceId,
                        principalTable: "AuthenticationMethodReference",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AuthorizationGrantAuthenticationMethodReference_AuthorizationGrant_AuthorizationGrantId",
                        column: x => x.AuthorizationGrantId,
                        principalTable: "AuthorizationGrant",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationGrantConsent",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    ConsentId = table.Column<int>(type: "int", nullable: false),
                    AuthorizationGrantId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    ConsentType = table.Column<int>(type: "int", nullable: false),
                    Resource = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationGrantConsent", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizationGrantConsent_AuthorizationGrant_AuthorizationGrantId",
                        column: x => x.AuthorizationGrantId,
                        principalTable: "AuthorizationGrant",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_AuthorizationGrantConsent_Consent_ConsentId",
                        column: x => x.ConsentId,
                        principalTable: "Consent",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Nonce",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Value = table.Column<string>(type: "nvarchar(max)", maxLength: 2147483647, nullable: false),
                    HashedValue = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    IssuedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    AuthorizationGrantId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Nonce", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Nonce_AuthorizationGrant_AuthorizationGrantId",
                        column: x => x.AuthorizationGrantId,
                        principalTable: "AuthorizationGrant",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Token",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Reference = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    Scope = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: true),
                    TokenType = table.Column<int>(type: "int", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    IssuedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    NotBefore = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Audience = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    Issuer = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "datetime2", nullable: true),
                    ClientId = table.Column<string>(type: "nvarchar(450)", nullable: true),
                    AuthorizationGrantId = table.Column<string>(type: "nvarchar(450)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Token", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Token_AuthorizationGrant_AuthorizationGrantId",
                        column: x => x.AuthorizationGrantId,
                        principalTable: "AuthorizationGrant",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_Token_Client_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Client",
                        principalColumn: "Id");
                });

            migrationBuilder.InsertData(
                table: "AuthenticationMethodReference",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 1, "pwd" },
                    { 2, "mfa" },
                    { 3, "sms" },
                    { 4, "face" },
                    { 5, "fpt" },
                    { 6, "geo" },
                    { 7, "iris" },
                    { 8, "kba" },
                    { 9, "mca" },
                    { 10, "otp" },
                    { 11, "pin" },
                    { 12, "hwk" },
                    { 13, "pop" },
                    { 14, "swk" },
                    { 15, "retina" },
                    { 16, "rba" },
                    { 17, "sc" },
                    { 18, "tel" },
                    { 19, "user" },
                    { 20, "vbm" },
                    { 21, "wia" }
                });

            migrationBuilder.InsertData(
                table: "Claim",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 1, "name" },
                    { 2, "given_name" },
                    { 3, "family_name" },
                    { 4, "middle_name" },
                    { 5, "nickname" },
                    { 6, "preferred_username" },
                    { 7, "profile" },
                    { 8, "picture" },
                    { 9, "website" },
                    { 10, "email" },
                    { 11, "email_verified" },
                    { 12, "gender" },
                    { 13, "birthdate" },
                    { 14, "zoneinfo" },
                    { 15, "locale" },
                    { 16, "phone_number" },
                    { 17, "phone_number_verified" },
                    { 18, "address" },
                    { 19, "updated_at" },
                    { 20, "roles" }
                });

            migrationBuilder.InsertData(
                table: "GrantType",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 1, "authorization_code" },
                    { 2, "client_credentials" },
                    { 3, "refresh_token" }
                });

            migrationBuilder.InsertData(
                table: "ResponseType",
                columns: new[] { "Id", "Name" },
                values: new object[] { 1, "code" });

            migrationBuilder.InsertData(
                table: "Scope",
                columns: new[] { "Id", "Name" },
                values: new object[,]
                {
                    { 1, "openid" },
                    { 2, "offline_access" },
                    { 3, "profile" },
                    { 4, "address" },
                    { 5, "email" },
                    { 6, "phone" },
                    { 7, "authserver:userinfo" },
                    { 8, "authserver:register" },
                    { 9, "grant_management_query" },
                    { 10, "grant_management_revoke" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationContextReference_Name",
                table: "AuthenticationContextReference",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthenticationMethodReference_Name",
                table: "AuthenticationMethodReference",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCode_AuthorizationGrantId",
                table: "AuthorizationCode",
                column: "AuthorizationGrantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrant_AuthenticationContextReferenceId",
                table: "AuthorizationGrant",
                column: "AuthenticationContextReferenceId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrant_ClientId",
                table: "AuthorizationGrant",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrant_SessionId",
                table: "AuthorizationGrant",
                column: "SessionId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrantAuthenticationMethodReference_AuthorizationGrantId",
                table: "AuthorizationGrantAuthenticationMethodReference",
                column: "AuthorizationGrantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrantConsent_AuthorizationGrantId",
                table: "AuthorizationGrantConsent",
                column: "AuthorizationGrantId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationGrantConsent_ConsentId",
                table: "AuthorizationGrantConsent",
                column: "ConsentId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizeMessage_ClientId",
                table: "AuthorizeMessage",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizeMessage_Reference",
                table: "AuthorizeMessage",
                column: "Reference",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Claim_Name",
                table: "Claim",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Client_ClientUri",
                table: "Client",
                column: "ClientUri");

            migrationBuilder.CreateIndex(
                name: "IX_Client_SectorIdentifierId",
                table: "Client",
                column: "SectorIdentifierId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientAuthenticationContextReference_AuthenticationContextReferenceId",
                table: "ClientAuthenticationContextReference",
                column: "AuthenticationContextReferenceId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientGrantType_GrantTypeId",
                table: "ClientGrantType",
                column: "GrantTypeId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientResponseType_ResponseTypeId",
                table: "ClientResponseType",
                column: "ResponseTypeId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientScope_ScopeId",
                table: "ClientScope",
                column: "ScopeId");

            migrationBuilder.CreateIndex(
                name: "IX_Consent_ClaimId",
                table: "Consent",
                column: "ClaimId");

            migrationBuilder.CreateIndex(
                name: "IX_Consent_ClientId",
                table: "Consent",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_Consent_ScopeId",
                table: "Consent",
                column: "ScopeId");

            migrationBuilder.CreateIndex(
                name: "IX_Consent_SubjectIdentifierId",
                table: "Consent",
                column: "SubjectIdentifierId");

            migrationBuilder.CreateIndex(
                name: "IX_Contact_ClientId",
                table: "Contact",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_GrantType_Name",
                table: "GrantType",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Nonce_AuthorizationGrantId",
                table: "Nonce",
                column: "AuthorizationGrantId");

            migrationBuilder.CreateIndex(
                name: "IX_PostLogoutRedirectUri_ClientId",
                table: "PostLogoutRedirectUri",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_RedirectUri_ClientId",
                table: "RedirectUri",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_RequestUri_ClientId",
                table: "RequestUri",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_ResponseType_Name",
                table: "ResponseType",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Scope_Name",
                table: "Scope",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SectorIdentifier_Uri",
                table: "SectorIdentifier",
                column: "Uri",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Session_SubjectIdentifierId",
                table: "Session",
                column: "SubjectIdentifierId");

            migrationBuilder.CreateIndex(
                name: "IX_Token_AuthorizationGrantId",
                table: "Token",
                column: "AuthorizationGrantId");

            migrationBuilder.CreateIndex(
                name: "IX_Token_ClientId",
                table: "Token",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_Token_Reference",
                table: "Token",
                column: "Reference",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuthorizationCode");

            migrationBuilder.DropTable(
                name: "AuthorizationGrantAuthenticationMethodReference");

            migrationBuilder.DropTable(
                name: "AuthorizationGrantConsent");

            migrationBuilder.DropTable(
                name: "AuthorizeMessage");

            migrationBuilder.DropTable(
                name: "ClientAuthenticationContextReference");

            migrationBuilder.DropTable(
                name: "ClientGrantType");

            migrationBuilder.DropTable(
                name: "ClientResponseType");

            migrationBuilder.DropTable(
                name: "ClientScope");

            migrationBuilder.DropTable(
                name: "Contact");

            migrationBuilder.DropTable(
                name: "Nonce");

            migrationBuilder.DropTable(
                name: "PostLogoutRedirectUri");

            migrationBuilder.DropTable(
                name: "RedirectUri");

            migrationBuilder.DropTable(
                name: "RequestUri");

            migrationBuilder.DropTable(
                name: "Token");

            migrationBuilder.DropTable(
                name: "AuthenticationMethodReference");

            migrationBuilder.DropTable(
                name: "Consent");

            migrationBuilder.DropTable(
                name: "GrantType");

            migrationBuilder.DropTable(
                name: "ResponseType");

            migrationBuilder.DropTable(
                name: "AuthorizationGrant");

            migrationBuilder.DropTable(
                name: "Claim");

            migrationBuilder.DropTable(
                name: "Scope");

            migrationBuilder.DropTable(
                name: "AuthenticationContextReference");

            migrationBuilder.DropTable(
                name: "Client");

            migrationBuilder.DropTable(
                name: "Session");

            migrationBuilder.DropTable(
                name: "SectorIdentifier");

            migrationBuilder.DropTable(
                name: "SubjectIdentifier");
        }
    }
}
