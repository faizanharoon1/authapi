using System.Text.Json.Serialization;
using System.Text.Json;
using System;
using Startup.Tests;
using Microsoft.Extensions.DependencyInjection;
using BLL.Services;
using BLL.Models.Users;

namespace Services.Tests
{
    public class UserServiceTests : IClassFixture<CommonFixture>
    {
        private readonly ServiceProvider _serviceProvider;
        private readonly JsonSerializerOptions jsonOptions;

        public UserServiceTests(CommonFixture fixture)
        {

            _serviceProvider = fixture.ServiceProvider;

            jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            };
            jsonOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));


        }
        [Fact]
        [Trait("Category", "Integration")]
        public async Task AuthSuccess_Tests()
        {
            using var scope = _serviceProvider.CreateScope();
            var service = scope.ServiceProvider.GetRequiredService<IUserService>();

            var data = await service.Authenticate(new AuthenticateRequest() { Username = "test@test.com", Password = "12345678" },
                "127.0.0.1");
            Assert.NotNull(data);
            Assert.NotNull(data.Access_token);
        }
        [Fact]
        [Trait("Category", "Integration")]
        public async Task RefreshTokenTest_Tests()
        {
            using var scope = _serviceProvider.CreateScope();
            var service = scope.ServiceProvider.GetRequiredService<IUserService>();
            var dataAuth = await service.Authenticate(new AuthenticateRequest() { Username = "test@test.com", Password = "12345678" },
             "127.0.0.1");
            var data = await service.RefreshToken(dataAuth.RefreshToken,
                "127.0.0.1");
            Assert.NotNull(data);
            Assert.NotNull(data.Access_token);
        }
    }
}