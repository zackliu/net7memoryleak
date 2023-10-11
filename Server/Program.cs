using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using Microsoft.Azure.EventGrid;
using Microsoft.Rest;
using System.Globalization;
using System.Collections.Concurrent;
using System.Text;

namespace EventGrid
{
    public class Program
    {
        static long i = 0;

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var app = builder.Build();

            app.UseRouting();

            app.Map("/test", (context) =>
            {
                context.Response.StatusCode = 200;
                var count = Interlocked.Increment(ref i);
                if (count % 100 == 0)
                {
                    Console.WriteLine($"Done {count}");
                }
                return Task.CompletedTask;
            });
            app.Run();
        }
    }
}