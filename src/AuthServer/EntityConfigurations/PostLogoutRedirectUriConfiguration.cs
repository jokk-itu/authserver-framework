﻿using AuthServer.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthServer.EntityConfigurations;
internal sealed class PostLogoutRedirectUriConfiguration : IEntityTypeConfiguration<PostLogoutRedirectUri>
{
    public void Configure(EntityTypeBuilder<PostLogoutRedirectUri> builder)
    {
        builder
            .Property(x => x.Uri)
            .HasMaxLength(255)
            .IsRequired();

        builder
            .HasOne(x => x.Client)
            .WithMany(x => x.PostLogoutRedirectUris)
            .IsRequired()
            .OnDelete(DeleteBehavior.Cascade);
    }
}