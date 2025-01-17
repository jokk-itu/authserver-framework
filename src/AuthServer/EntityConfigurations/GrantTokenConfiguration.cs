using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class GrantTokenConfiguration : IEntityTypeConfiguration<GrantToken>
{
    public void Configure(EntityTypeBuilder<GrantToken> builder)
    {
        builder
            .HasOne(x => x.AuthorizationGrant)
            .WithMany(x => x.GrantTokens)
            .IsRequired()
            .OnDelete(DeleteBehavior.ClientCascade);
    }
}