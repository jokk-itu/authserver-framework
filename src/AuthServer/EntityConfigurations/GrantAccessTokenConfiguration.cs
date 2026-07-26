using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal class GrantAccessTokenConfiguration : IEntityTypeConfiguration<GrantAccessToken>
{
    public void Configure(EntityTypeBuilder<GrantAccessToken> builder)
    {
        builder
            .HasBaseType<GrantToken>();

        builder
            .Property(x => x.AuthorizationDetails)
            .HasMaxLength(2048)
            .IsRequired(false)
            .HasColumnName(nameof(GrantAccessToken.AuthorizationDetails));
    }
}