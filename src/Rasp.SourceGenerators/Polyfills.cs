using System.ComponentModel;

namespace System.Runtime.CompilerServices
{
    // ELITE: Habilita o uso de 'record' e 'init' em projetos .NET Standard 2.0
    // O compilador C# suporta a feature, mas o runtime antigo não tem o tipo marcador.
    // Nós o definimos manualmente aqui.
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static class IsExternalInit { }
}