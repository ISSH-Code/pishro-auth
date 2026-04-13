# Multi-stage Dockerfile for Pishro.Auth.Server
# Build context expected: pishro-auth/src

# Stage 1: restore
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS restore
WORKDIR /src

COPY Pishro.Auth.Domain/Pishro.Auth.Domain.csproj Pishro.Auth.Domain/
COPY Pishro.Auth.Application/Pishro.Auth.Application.csproj Pishro.Auth.Application/
COPY Pishro.Auth.Infrastructure/Pishro.Auth.Infrastructure.csproj Pishro.Auth.Infrastructure/
COPY Pishro.Auth.Server/Pishro.Auth.Server.csproj Pishro.Auth.Server/

RUN dotnet restore Pishro.Auth.Server/Pishro.Auth.Server.csproj

# Stage 2: publish
FROM restore AS publish
COPY . .
RUN dotnet publish Pishro.Auth.Server/Pishro.Auth.Server.csproj \
    --no-restore -c Release -o /app/publish

# Stage 3: runtime
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=publish /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "Pishro.Auth.Server.dll"]
