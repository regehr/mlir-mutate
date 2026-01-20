#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/Signals.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <utility>

using namespace std;
using namespace llvm;

namespace {

cl::OptionCategory mutatorArgs("KnownBits Analyzer options");

cl::list<std::string> InputFileNames(cl::Positional, cl::desc("<Input files>"),
                                     cl::OneOrMore);

ExitOnError ExitOnErr;

LLVMContext Context;

std::unique_ptr<Module> openInputFile(const string &InputFilename) {
  auto MB = ExitOnErr(errorOrToExpected(MemoryBuffer::getFile(InputFilename)));
  SMDiagnostic Diag;
  auto M = getLazyIRModule(std::move(MB), Diag, Context,
                           /*ShouldLazyLoadMetadata=*/true);
  if (!M) {
    Diag.print("", errs(), false);
    return 0;
  }
  ExitOnErr(M->materializeAll());
  return M;
}

long totalBits, totalKB;

void processFile(const string &fn) {
  outs() << "file: " << fn << "\n";
    
  auto M = openInputFile(fn);
  if (!M.get()) {
    errs() << "Could not read input file from '" << fn << "'\n";
    return;
  }

  const auto DL = M->getDataLayout();
  for (auto &F : *M.get()) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        auto Ty = I.getType();

        if (false) {
          I.print(outs());
          outs() << "\n";        
          Ty->print(outs());
          outs() << "\n";
          outs().flush();
        }
        
        if (Ty->isIntOrIntVectorTy()) { //  || Ty->isPtrOrPtrVectorTy()) {
          auto IW = Ty->getScalarSizeInBits();
          KnownBits KB(IW);
          computeKnownBits(&I, KB, DL);
          totalBits += IW;
          totalKB += (KB.Zero | KB.One).popcount();
        }
      }
    }
  }
}

} // namespace

int main(int argc, char **argv) {
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  InitLLVM X(argc, argv);
  EnableDebugBuffering = true;

  std::string Usage =
      R"EOF(Alive-mutate, a stand-alone LLVM IR fuzzer cooperates  with Alive2. Alive2 version: )EOF";
  Usage += R"EOF(
see alive-mutate --help for more options,
)EOF";

  cl::HideUnrelatedOptions(mutatorArgs);
  cl::ParseCommandLineOptions(argc, argv, Usage);

  for (auto fn : InputFileNames) {
    processFile(fn);
  }

  outs() << "Total known bits: " << totalKB << "\n";
  outs() << "Total bits: " << totalBits << "\n";
  outs() << "Known percent = " << ((double)100 * totalKB / totalBits) << "\n";

  return 0;
}
