using Grpc.Core;
using Rasp.Benchmarks.Models;
using Rasp.Benchmarks;

namespace Rasp.Benchmarks.Stubs;

// This stub exists solely to trigger the RASP Source Generator.
// It will generate: DeepTargetServiceRaspInterceptor
public class DeepTargetService : DeepRequestService.DeepRequestServiceBase
{
    public override Task<DeepRequest> DeepOperation(DeepRequest request, ServerCallContext context)
    {
        return Task.FromResult(request);
    }
}