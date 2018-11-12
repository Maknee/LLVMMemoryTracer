#pragma once

#include "llvm/Support/CommandLine.h"

#define APPLICATION_NAME "memory-tracer"

namespace MemoryTracer
{
  namespace CommandLineOptions
  {
    using namespace llvm;

    cl::OptionCategory memory_tracer_option_category(APPLICATION_NAME);

    cl::list<std::string> struct_options(cl::desc("Trace following structs"),
                                         cl::value_desc("string of structs"),
                                         cl::CommaSeparated,
                                         cl::ZeroOrMore,
                                         cl::cat(memory_tracer_option_category));
  }
}
