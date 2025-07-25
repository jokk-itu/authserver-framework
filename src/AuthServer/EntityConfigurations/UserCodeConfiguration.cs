using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal class UserCodeConfiguration : IEntityTypeConfiguration<UserCode>
{
    public void Configure(EntityTypeBuilder<UserCode> builder)
    {
        builder
            .HasOne(x => x.DeviceCode)
            .WithOne()
            .HasForeignKey<UserCode>("DeviceCodeId")
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);

        builder
            .Property(x => x.Value)
            .HasMaxLength(16)
            .IsRequired();

        builder
            .HasIndex(x => x.Value);
    }
}