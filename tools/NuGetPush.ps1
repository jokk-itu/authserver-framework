dotnet nuget push "*.nupkg" -s "https://nuget.pkg.github.com/jokk-itu/index.json" -k $Env:GithubToken