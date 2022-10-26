using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace WebApi.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                    ,
                    Title = table.Column<string>(type: "varchar(10)", maxLength: 10, nullable: true),
                    FirstName = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: true),
                    LastName = table.Column<string>(type: "varchar(20)", maxLength: 20, nullable: true),
                    Email = table.Column<string>(type: "varchar(40)", maxLength: 40, nullable: false),
                    PasswordHash = table.Column<string>(type: "varchar(200)", maxLength: 200, nullable: true),
                    AcceptTerms = table.Column<bool>(nullable: false),
                    Role = table.Column<int>(nullable: false),
                    VerificationToken = table.Column<string>(nullable: true),
                    Verified = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    ResetToken = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    ResetTokenExpires = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    PasswordReset = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    Created = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: false),
                    Updated = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                    table.Annotation("MySQL:AutoIncrement", true);
                });

            migrationBuilder.CreateTable(
                name: "RefreshToken",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("MySQL:AutoIncrement", true),
                    UserId = table.Column<int>(nullable: false),
                    Token = table.Column<string>(nullable: true),
                    Expires = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    Created = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: false),
                    CreatedByIp = table.Column<string>(nullable: true),
                    Revoked = table.Column<DateTime>(type: "datetime(6)", maxLength: 6, nullable: true),
                    RevokedByIp = table.Column<string>(nullable: true),
                    ReplacedByToken = table.Column<string>(nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshToken", x => x.Id);
                    //table.ForeignKey(
                    //    name: "FK_RefreshToken_Users_UserId",
                    //    column: x => x.UserId,
                    //    principalTable: "Users",
                    //    principalColumn: "Id",
                    //    onDelete: ReferentialAction.Cascade);
                }
                );

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_UserId",
                table: "RefreshToken",
                column: "UserId");

            migrationBuilder.Sql(@"
                    ALTER TABLE `ef`.`users` 
                    CHANGE COLUMN `Id` `Id` INT NOT NULL AUTO_INCREMENT ;

                    ALTER TABLE `ef`.`refreshtoken` 
                    CHANGE COLUMN `Id` `Id` INT NOT NULL AUTO_INCREMENT ;

                                ");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RefreshToken");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
