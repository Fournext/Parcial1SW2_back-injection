"""
Servidor web simulado con Flask para pruebas de integración con Playwright.
Ofrece una interfaz HTML con chat interactivo y un endpoint POST /mock/chat.
"""
from flask import Flask, request, jsonify, render_template_string

mock_app = Flask(__name__)

HTML_CHAT = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Laboratorio Mock AI Chat</title>
</head>
<body>
    <h1>Asistente Virtual con IA</h1>
    <div id="chat-box">
        <textarea id="prompt" placeholder="Escribe tu mensaje para la IA..."></textarea>
        <button id="btn-enviar" type="submit">Enviar Consulta</button>
    </div>
    <div id="respuesta"></div>

    <script>
        document.getElementById('btn-enviar').addEventListener('click', async () => {
            const promptVal = document.getElementById('prompt').value;
            const res = await fetch('/mock/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer test_mock_token_abc'
                },
                body: JSON.stringify({
                    conversation: {
                        messages: [
                            { role: 'user', content: promptVal }
                        ]
                    }
                })
            });
            const data = await res.json();
            document.getElementById('respuesta').innerText = data.reply;
        });
    </script>
</body>
</html>
"""

@mock_app.route('/')
def index():
    return render_template_string(HTML_CHAT)

@mock_app.route('/mock/chat', methods=['POST'])
def chat():
    datos = request.get_json(silent=True) or {}
    return jsonify({
        "reply": "Hola, soy el modelo de IA simulado. He recibido tu mensaje correctamente.",
        "echo": datos
    })

if __name__ == '__main__':
    mock_app.run(port=5050)
