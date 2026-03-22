using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;

internal class AuthorizationDetailTypeConfiguration : IEntityTypeConfiguration<AuthorizationDetailType>
{
    public void Configure(EntityTypeBuilder<AuthorizationDetailType> builder)
    {
        builder
            .Property(x => x.Name)
            .HasMaxLength(255)
            .IsRequired();

        builder
            .HasIndex(s => s.Name)
            .IsUnique();
    }
}