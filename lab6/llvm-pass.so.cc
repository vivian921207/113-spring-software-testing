#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

struct LLVMPass : public PassInfoMixin<LLVMPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

PreservedAnalyses LLVMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *Int32Ty = IntegerType::getInt32Ty(Ctx);
  PointerType *Int8PtrTy = Type::getInt8PtrTy(Ctx);

  // 宣告 debug(int) 函式
  FunctionType *DebugFuncTy = FunctionType::get(Type::getVoidTy(Ctx), {Int32Ty}, false);
  FunctionCallee debug_func = M.getOrInsertFunction("debug", DebugFuncTy);
  ConstantInt *debug_arg = ConstantInt::get(Int32Ty, 48763);

  for (Function &F : M) {
    if (F.getName() != "main") continue;

    // 取得 main 的參數 argc, argv
    Argument *argc = F.getArg(0);
    Argument *argv = F.getArg(1);

    // 插入點：main 的開頭
    IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());

    // 1️⃣ 呼叫 debug(48763)
    IRB.CreateCall(debug_func, debug_arg);

    // 2️⃣ 將 argc 的所有用途替換為常數 48763
    argc->replaceAllUsesWith(debug_arg);

    // 3️⃣ 將 argv[1] 設為 "hayaku... motohayaku!"
    Value *argv1_ptr = IRB.CreateGEP(argv->getType()->getPointerElementType(), argv, ConstantInt::get(Int32Ty, 1));
    Value *str_val = IRB.CreateGlobalStringPtr("hayaku... motohayaku!");
    IRB.CreateStore(str_val, argv1_ptr);
  }

  return PreservedAnalyses::none();
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LLVMPass", "1.0",
    [](PassBuilder &PB) {
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel OL) {
          MPM.addPass(LLVMPass());
        });
    }};
}
