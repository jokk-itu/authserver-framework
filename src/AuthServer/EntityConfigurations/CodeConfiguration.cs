using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal class CodeConfiguration : IEntityTypeConfiguration<Code>
{
    public void Configure(EntityTypeBuilder<Code> builder)
    {
        builder
            .HasDiscriminator(x => x.CodeType)
            .HasValue<AuthorizationCode>(CodeType.AuthorizationCode)
            .HasValue<DeviceCode>(CodeType.DeviceCode)
            .HasValue<UserCode>(CodeType.UserCode);

        builder
            .Property(x => x.RawValue)
            .HasMaxLength(2048)
            .IsRequired();
    }
}