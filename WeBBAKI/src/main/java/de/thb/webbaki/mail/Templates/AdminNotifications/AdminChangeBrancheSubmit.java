package de.thb.webbaki.mail.Templates.AdminNotifications;

public class AdminChangeBrancheSubmit {

    public static String changeBrancheMail(String userFirstname, String userLastname, String userBranche, String username) {

        return "<!DOCTYPE html>\n" +
                "<html lang=\"de\" dir=\"ltr\">\n" +
                "  <head>\n" +
                "    <meta charset=\"utf-8\">\n" +
                "    <title></title>\n" +
                "  </head>\n" +
                "\n" +
                "  <style>\n" +
                "    p{\n" +
                "      font-size:16px;\n" +
                "    }\n" +
                "\n" +
                "    html {\n" +
                "      font-family: sans-serif;\n" +
                "      text-align:center;\n" +
                "      align-content:center;\n" +
                "    }\n" +
                "\n" +
                "    table {\n" +
                "      width:560px;\n" +
                "      border-collapse: collapse;\n" +
                "      border: 2px solid rgb(200,200,200);\n" +
                "      letter-spacing: 1px;\n" +
                "      font-size: 0.9rem;\n" +
                "    }\n" +
                "\n" +
                "    td, th {\n" +
                "      border: 1px solid rgb(190,190,190);\n" +
                "      padding: 10px 20px;\n" +
                "    }\n" +
                "\n" +
                "    th {\n" +
                "      background-color: rgb(235,235,235);\n" +
                "    }\n" +
                "\n" +
                "    td {\n" +
                "      text-align: center;\n" +
                "    }\n" +
                "\n" +
                "    tr:nth-child(even) td {\n" +
                "      background-color: rgb(250,250,250);\n" +
                "    }\n" +
                "\n" +
                "    tr:nth-child(odd) td {\n" +
                "      background-color: rgb(245,245,245);\n" +
                "    }\n" +
                "\n" +
                "    caption {\n" +
                "      padding: 10px;\n" +
                "    }\n" +
                "  </style>\n" +
                "\n" +
                "  <body>\n" +
                "    <h2 style=\"background-color:black; color: white; padding: 20px 0; margin: 0 auto;\">Neue Registrierung auf WebBaKI</h2>\n" +
                "    <p>Hallo " + userFirstname + " " + userLastname + ",</p>\n" +
                "    <p>Ein Mitglied der WebBaKI-Geschäftsstelle hat eine Rollenänderung bei folgendem Nutzer getätigt:</p>\n" +
                "    <div class=\"tabledata\" style=\"display:flex;align-items:center; justify-content:center\">\n" +
                "      <table style=\"\">\n" +
                "          <tr>\n" +
                "            <td>Nutzer: </td>\n" +
                "            <td>" + username + "</td>\n" +
                "          </tr>\n" +
                "          <tr>\n" +
                "            <td>Neue Branche: </td>\n" +
                "            <td>" + userBranche + "</td>\n" +
                "          </tr>\n" +
                "      </table>\n" +
                "    </div>\n" +
                "        <span></span>\n" +
                "      </p>\n" +
                "    <p>Mit freundlichen Grüßen</p>\n" +
                "    <p>Ihr WebBakI-Team</p>\n" +
                "  </body>\n" +
                "</html>\n";
    }

}

