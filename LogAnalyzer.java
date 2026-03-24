import java.util.regex.*;

public class LogAnalyzer {

    public static void analyze(String log) {

        int riskScore = 0;

        System.out.println("------ AI Secure Analysis ------");

        // Email
        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+");
        Matcher email = emailPattern.matcher(log);
        while (email.find()) {
            System.out.println("Email: " + email.group() + " | Risk: LOW");
            riskScore += 1;
        }

        // Password
        Pattern passwordPattern = Pattern.compile("password=\\w+");
        Matcher password = passwordPattern.matcher(log);
        while (password.find()) {
            System.out.println("Password Found | Risk: CRITICAL");
            riskScore += 5;
        }

        // API Key
        Pattern apiPattern = Pattern.compile("api_key=\\w+");
        Matcher api = apiPattern.matcher(log);
        while (api.find()) {
            System.out.println("API Key Found | Risk: HIGH");
            riskScore += 3;
        }

        // Stack Trace
        if (log.contains("Exception")) {
            System.out.println("Stack Trace Found | Risk: MEDIUM");
            riskScore += 2;
        }

        // Final Risk Level
        String riskLevel = "LOW";
        if (riskScore >= 7)
            riskLevel = "HIGH";
        else if (riskScore >= 4)
            riskLevel = "MEDIUM";

        System.out.println("Final Risk Level: " + riskLevel);

        // Insights
        System.out.println("---- Insights ----");
        if (log.contains("password") || log.contains("api_key")) {
            System.out.println("Sensitive credentials exposed");
        }
        if (log.contains("Exception")) {
            System.out.println("System error details leaked");
        }
    }

    public static void main(String[] args) {

        String log = "email=admin@company.com password=admin123 api_key=xyz ERROR Exception";

        analyze(log);
    }
}