using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal sealed class NonceConfiguration : IEntityTypeConfiguration<Nonce>
{
    public void Configure(EntityTypeBuilder<Nonce> builder)
    {
        builder
            .HasDiscriminator(x => x.NonceType)
            .HasValue<AuthorizationGrantNonce>(NonceType.AuthorizationGrantNonce)
            .HasValue<DPoPNonce>(NonceType.DPoPNonce);

        builder
            .Property(x => x.Value)
            .HasMaxLength(int.MaxValue)
            .IsRequired();

        builder
            .Property(x => x.HashedValue)
            .HasMaxLength(256)
            .IsRequired();
    }
}