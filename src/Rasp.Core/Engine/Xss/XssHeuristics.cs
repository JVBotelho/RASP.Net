using System.Buffers;

namespace Rasp.Core.Engine.Xss;

internal static class XssHeuristics
{
    // Tags que indicam alta probabilidade de execução de código (High Risk)
    // Se encontradas com atributos ou em contextos suspeitos, é bloqueio.
    private static readonly SearchValues<string> ExecutionTags = SearchValues.Create(
        ["<script", "<iframe", "<object", "<embed", "<applet", "<meta", "<link", "<style", "<template", "<noscript"], 
        StringComparison.OrdinalIgnoreCase);
    
    private static readonly SearchValues<string> SuspiciousTags = SearchValues.Create(
        ["<img", "<svg", "<video", "<audio", "<body", "<input", "<details", "<form"], 
        StringComparison.OrdinalIgnoreCase);

    // Protocolos que executam código
    private static readonly SearchValues<string> DangerousProtocols = SearchValues.Create(
        ["javascript:", "vbscript:", "data:text/html"], 
        StringComparison.OrdinalIgnoreCase);

    // Eventos DOM comuns (Expanded List)
    private static readonly string[] DomEvents = 
    [
        "onload", "onerror", "onclick", "onmouseover", "onfocus", 
        "onblur", "onchange", "onsubmit", "onkeydown", "onkeyup",
        "onmouseenter", "onmouseleave", "ontoggle", "onanimationstart"
    ];

    public static double ScorePatterns(ReadOnlySpan<char> input)
    {
        // 1. High Risk Tags
        // Para Stored XSS, tags como <script> e <iframe> são perigosas por padrão.
        // Mesmo em blogs técnicos, a sanitização ideal é na saída, mas o RASP de entrada
        // deve ser conservador com tags de execução explícita.
        if (input.ContainsAny(ExecutionTags))
        {
             return 1.0;
        }

        // 2. Protocolos Perigosos (ex: <a href="javascript:...">)
        if (input.ContainsAny(DangerousProtocols))
        {
            return 1.0;
        }

        // 3. Event Handlers (Detecta on...=)
        // Isso pega <img src=x onerror=alert(1)> e <svg onload=...>
        // Lógica robusta contra ofuscação de espaços.
        if (ScoreEventHandlers(input) >= 1.0)
        {
            return 1.0;
        }
        
        // 4. Suspicious Tags + Contexto de Atributo
        // Se temos uma tag como <img> E um sinal de atribuição (=), aumentamos a suspeita.
        // O ScoreEventHandlers já deve ter pego o 'onerror', mas isso serve como defesa em profundidade.
        if (input.ContainsAny(SuspiciousTags))
        {
            // Se contiver '=' e uma tag suspeita, é um sinal de alerta.
            // No entanto, <img src="safe.jpg"> é válido.
            // O bloqueio real deve vir se o atributo for perigoso (javascript:, on*).
            // Como já checamos protocolos e eventos acima, aqui servimos como fallback 
            // para estruturas anômalas ou polyglots que escaparam.
                
            // Exemplo: <svg/onload=alert(1)> (sem espaço)
            // O ScoreEventHandlers pega o 'onload', então aqui é redundante para bloqueio,
            // mas útil para sinalizar risco elevado em sistemas de pontuação.
            return 0.5; // Warning level, não bloqueio direto sem confirmação
        }
        return 0.0; 
    }

    private static double ScoreEventHandlers(ReadOnlySpan<char> input)
    {
        // Varredura linear otimizada para encontrar eventos
        foreach (var evt in DomEvents)
        {
            int idx = input.IndexOf(evt.AsSpan(), StringComparison.OrdinalIgnoreCase);
            
            // Loop para encontrar todas as ocorrências do evento na string
            while (idx >= 0)
            {
                // Verifica o que vem DEPOIS do nome do evento
                // Ex: "onload   =  alert"
                var afterEvent = input.Slice(idx + evt.Length);
                
                // Pula espaços em branco e caracteres de controle (Zero-Alloc trim)
                int i = 0;
                while (i < afterEvent.Length && (char.IsWhiteSpace(afterEvent[i]) || afterEvent[i] < 32)) 
                {
                    i++;
                }

                // Se o próximo char significativo for '=', bingo!
                if (i < afterEvent.Length && afterEvent[i] == '=')
                {
                    return 1.0;
                }

                // Procura próxima ocorrência
                var nextSlice = input.Slice(idx + 1);
                int nextIdx = nextSlice.IndexOf(evt.AsSpan(), StringComparison.OrdinalIgnoreCase);
                if (nextIdx == -1) break;
                idx += nextIdx + 1;
            }
        }

        return 0.0;
    }
}