using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal class ClientAccessTokenConfiguration : IEntityTypeConfiguration<ClientAccessToken>
{
    public void Configure(EntityTypeBuilder<ClientAccessToken> builder)
    {
        builder
            .HasBaseType<ClientToken>();

        builder
            .Property(x => x.AuthorizationDetails)
            .HasMaxLength(2048)
            .IsRequired(false)
            .HasColumnName(nameof(ClientAccessToken.AuthorizationDetails));
    }
}