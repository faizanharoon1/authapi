using BLL.Services;
using DAL;
using DAL.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace Startup.Tests
{
    public class CommonFixture
    {
        public CommonFixture()
        {
            var environment = "Development";
            environment = !string.IsNullOrEmpty(environment) ? $".{environment}" : "";
            Console.WriteLine("Environment appsettings file:" + $"appsettings{environment}.json");
            string? path = Path.GetDirectoryName(Assembly.GetEntryAssembly()?.Location ?? "");
            if (string.IsNullOrEmpty(path))
                throw new InvalidDataException();

            var builder = new ConfigurationBuilder()
                                          .SetBasePath(path)
                                          .AddJsonFile($"appsettings{environment}.json", false)
                                          .AddEnvironmentVariables();


            var configuration = builder.Build();
            var services = new ServiceCollection();
            //global settings

            #region Configuration

            //Registering settings as IOptions
            services.AddSingleton<IConfiguration>(configuration);
            services.AddOptions();
            services.Configure<AppSettings>(configuration.GetSection(nameof(AppSettings)));
            services.Configure<ConnectionStrings>(configuration.GetSection(nameof(ConnectionStrings)));
            #endregion Configuration
            FinalizeStartup(services);

            ServiceProvider = services.BuildServiceProvider();
        }

        public void FinalizeStartup(IServiceCollection services)
        {
            services.AddHttpClient();

            #region Add services
            services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());



            // configure DI for application services
            services.AddSingleton<IDbContext, DbContext>();
            services.AddSingleton<IDefaultSQLPolicy, DefaultSQLPolicy>();
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<IUserService, UserService>();

            #endregion
        }


        public ServiceProvider ServiceProvider { get; private set; }
    }
}
