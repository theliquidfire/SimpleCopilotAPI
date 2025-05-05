using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Swashbuckle.AspNetCore.Annotations;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Reflection.Metadata;

string myKey = "Once-upon-a-time-in-a-land-far-away";

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.EnableAnnotations();

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your token in the text input below.\n\nExample: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "your-issuer",
            ValidAudience = "your-audience",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(myKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// User model
// Thread-safe user collection
var users = new ConcurrentDictionary<int, User>();
var userIdCounter = 0;

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";
        var error = new { Message = "An unexpected error occurred. Please try again later." };
        await context.Response.WriteAsJsonAsync(error);
    });
});

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<RequestResponseLoggingMiddleware>();
app.UseSwagger();
app.UseSwaggerUI();

app.MapPost("/login", (string username, string password) =>
{
    // Replace this with your actual user validation logic
    if (username == "admin" && password == "password")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(myKey); // Use the same key as in TokenValidationParameters
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, username)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = "your-issuer", // Match the issuer in TokenValidationParameters
            Audience = "your-audience" // Match the audience in TokenValidationParameters
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return Results.Ok(new { Token = tokenHandler.WriteToken(token) });
    }

    return Results.Unauthorized();
});

// Create User
app.MapPost("/users", (User user) =>
{
    if (string.IsNullOrWhiteSpace(user.Name))
    {
        return Results.BadRequest("User name cannot be empty or null.");
    }
    if (user.Age <= 0)
    {
        return Results.BadRequest("User age must be greater than zero.");
    }
    var userId = System.Threading.Interlocked.Increment(ref userIdCounter);
    user.Id = userId;
    users[userId] = user;
    return Results.Created($"/users/{user.Id}", user);
})
.WithMetadata(new SwaggerOperationAttribute("Create a new user", "Adds a new user to the system"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status201Created, "User created successfully"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status400BadRequest, "Invalid user data"));

// Get All Users
app.MapGet("/users", () => Results.Ok(users.Values))
.RequireAuthorization();

// Get User by ID
app.MapGet("/users/{id}", (int id) =>
{
    return users.TryGetValue(id, out var user) ? Results.Ok(user) : Results.NotFound();
})
.WithMetadata(new SwaggerOperationAttribute("Get a user by ID", "Retrieves a user by their unique ID"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status200OK, "User retrieved successfully"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status404NotFound, "User not found"));

// Update User
app.MapPut("/users/{id}", (int id, User updatedUser) =>
{
    if (string.IsNullOrWhiteSpace(updatedUser.Name))
    {
        return Results.BadRequest("User name cannot be empty or null.");
    }
    if (updatedUser.Age <= 0)
    {
        return Results.BadRequest("User age must be greater than zero.");
    }
    if (!users.ContainsKey(id)) return Results.NotFound();

    users[id] = new User
    {
        Id = id,
        Name = updatedUser.Name,
        Age = updatedUser.Age
    };
    return Results.Ok(users[id]);
})
.WithMetadata(new SwaggerOperationAttribute("Update a user", "Updates the details of an existing user"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status200OK, "User updated successfully"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status400BadRequest, "Invalid user data"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status404NotFound, "User not found"));

// Delete User
app.MapDelete("/users/{id}", (int id) =>
{
    return users.TryRemove(id, out var user) ? Results.Ok(user) : Results.NotFound();
})
.WithMetadata(new SwaggerOperationAttribute("Delete a user", "Deletes a user by their unique ID"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status200OK, "User deleted successfully"))
.WithMetadata(new SwaggerResponseAttribute(StatusCodes.Status404NotFound, "User not found"));

app.Run();

public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public int Age { get; set; } = 0;
}

public class RequestResponseLoggingMiddleware
{
    private readonly RequestDelegate _next;

    public RequestResponseLoggingMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Log the request
        context.Request.EnableBuffering();
        var requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();
        context.Request.Body.Position = 0;
        Console.WriteLine($"Request: {context.Request.Method} {context.Request.Path} - Body: {requestBody}");

        // Capture and log the response
        var originalResponseBodyStream = context.Response.Body;
        using var responseBodyStream = new MemoryStream();
        context.Response.Body = responseBodyStream;

        await _next(context);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        var responseBody = await new StreamReader(context.Response.Body).ReadToEndAsync();
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        Console.WriteLine($"Response: {context.Response.StatusCode} - Body: {responseBody}");

        await responseBodyStream.CopyToAsync(originalResponseBodyStream);
    }
}