using DAL;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Reflection;

namespace Startup.Tests
{
    public class CommonFixture
    {
        public CommonFixture()
        {
            var environment = "development";
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
            //  <--- bind Configuration to IOptions<ConfigSettings>  ---->
            //One advantage to using IOptions<T> or more specifically IOptionsSnapshot is
            //that it can detect changes to the configuration source and
            //reload configuration as the application is running.
            services.AddOptions();

            services.Configure<IOptions<AppSettings>>(options => configuration.GetSection("AppSettings").Bind(options));
            services.Configure<IOptions<ConnectionStrings>>(options => configuration.GetSection("ConnectionStrings").Bind(options));

            #endregion Configuration

            // Registering Dependecy Injections
            //---------------------------------------------------------------------------------------------------------------------------            
            //   services.AddSingleton<IUserGroupAccessProvider, UserGroupAccessProvider>();
            // services.AddLogging(loggingBuilder => loggingBuilder.AddSerilog(dispose: true));
            FinalizeStartup(services);

            //SqlMapper.AddTypeHandler(typeof(List<ImpressionsAgeGenderType>), new JsonObjectTypeHandler());
            //SqlMapper.AddTypeHandler(typeof(Dictionary<string, int>), new JsonObjectTypeHandler());
            //SqlMapper.AddTypeHandler(typeof(ImpressionsAgeGenderSums), new JsonObjectTypeHandler());

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
