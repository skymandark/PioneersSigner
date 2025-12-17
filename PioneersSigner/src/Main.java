import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.Headers;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Main {

    // Fixed Token للتحقق من الهوية
    private static final String FIXED_TOKEN = "pioneers2024Token!";

    public static void main(String[] args) throws Exception {

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        // Endpoint for Sign - يرجع signature فقط
        server.createContext("/Sign", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    if (!validateToken(exchange)) {
                        sendErrorResponse(exchange, 401, "Unauthorized: Invalid token");
                        return;
                    }
                    handleSigningRequest(exchange, "sign");
                } catch (Exception e) {
                    try {
                        sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            } else if ("OPTIONS".equals(exchange.getRequestMethod())) {
                try {
                    handleOptionsRequest(exchange);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    sendErrorResponse(exchange, 405, "Method not allowed");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        // Endpoint for SignInvoice - يرجع الفاتورة كاملة
        server.createContext("/SignedInvoice", exchange -> {
            if ("POST".equals(exchange.getRequestMethod())) {
                try {
                    if (!validateToken(exchange)) {
                        sendErrorResponse(exchange, 401, "Unauthorized: Invalid token");
                        return;
                    }
                    handleSigningRequest(exchange, "signInvoice");
                } catch (Exception e) {
                    try {
                        sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                }
            } else if ("OPTIONS".equals(exchange.getRequestMethod())) {
                try {
                    handleOptionsRequest(exchange);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    sendErrorResponse(exchange, 405, "Method not allowed");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        server.start();
        System.out.println("Server running on http://localhost:8080/");
        System.out.println("Endpoints:");
        System.out.println("  - POST /Sign (Returns signature only)");
        System.out.println("  - POST /SignedInvoice (Returns full invoice with signature)");
        System.out.println("Fixed Token: " + FIXED_TOKEN);
    }

    /**
     * التحقق من صحة الـ Token في رأس الطلب
     */
    private static boolean validateToken(HttpExchange exchange) {
        try {
            Headers headers = exchange.getRequestHeaders();
            String authHeader = headers.getFirst("Authorization");

            if (authHeader == null || authHeader.trim().isEmpty()) {
                System.out.println(" Missing Authorization header");
                return false;
            }

            // توقع شكل: "Bearer pioneers2024Token!" أو "pioneers2024Token!"
            String token = authHeader.trim();
            if (token.startsWith("Bearer ")) {
                token = token.substring(7).trim();
            }

            boolean isValid = FIXED_TOKEN.equals(token);
            System.out.println(" Token validation: " + (isValid ? "VALID" : "INVALID"));

            return isValid;
        } catch (Exception e) {
            System.out.println(" Token validation error: " + e.getMessage());
            return false;
        }
    }

    private static void handleSigningRequest(HttpExchange exchange, String endpointType) throws Exception {
        InputStream is = exchange.getRequestBody();
        String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        CadesBesSigner cadesBesSigner = new CadesBesSigner();

        String response = null;
        try {
            if ("sign".equals(endpointType)) {
                response = cadesBesSigner.startSigning(json);
            } else if ("signInvoice".equals(endpointType)) {
                response = cadesBesSigner.startInvoiceSigning(json);
            }
        } catch (Exception e) {
            response = "{\"status\":\"error\",\"message\":\"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        exchange.sendResponseHeaders(200, response.getBytes(StandardCharsets.UTF_8).length);

        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    /**
     * معالجة طلبات OPTIONS لـ CORS
     */
    private static void handleOptionsRequest(HttpExchange exchange) throws Exception {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.sendResponseHeaders(200, -1);
        exchange.getResponseBody().close();
    }

    /**
     * إرسال ردود الخطأ
     */
    private static void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws Exception {
        String response = "{\"status\":\"error\",\"message\":\"" + message + "\"}";

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");

        exchange.sendResponseHeaders(statusCode, response.getBytes(StandardCharsets.UTF_8).length);

        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    // Very simple extraction (not full JSON parser)
    private static String extract(String json, String field) {
        try {
            int pos = json.indexOf(field);
            if (pos == -1) return "";
            int start = json.indexOf(":", pos) + 1;
            int end = json.indexOf(",", start);
            if (end == -1) end = json.indexOf("}", start);
            return json.substring(start, end).replace("\"", "").trim();
        } catch (Exception e) {
            return "";
        }
    }
}