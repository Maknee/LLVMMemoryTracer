#include "llvm/ADT/SmallVector.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/PassSupport.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/Debug.h"

#include <random>
#include <sstream>
#include <set>

#include "command-line-options.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/LegacyPassManager.h"

using namespace llvm;

#define EXIT_WITH_MESSAGE(...) \
  llvm::errs() << __VA_ARGS__; \
  exit(-1); \

LLVMContext llvm_context;

Module *makeLLVMModule() {
  Module *mod = new Module("sum.ll", llvm_context);
  mod->setDataLayout("e-m:w-i64:64-f80:128-n8:16:32:64-S128");
  mod->setTargetTriple("x86_64-pc-windows-msvc19.15.26726");

  SmallVector<Type *, 2> function_args{
      IntegerType::getInt32Ty(mod->getContext()),
      IntegerType::getInt32Ty(mod->getContext())};

  FunctionType *function_type = FunctionType::get(
      IntegerType::getInt32Ty(mod->getContext()), function_args, false);

  Function *function =
      Function::Create(function_type, GlobalValue::ExternalLinkage, "add", mod);
  function->setCallingConv(CallingConv::C);

  Function::arg_iterator arg_begin = function->arg_begin();
  Value *v_a = arg_begin;
  v_a->setName("a");
  arg_begin++;
  Value *v_b = arg_begin;
  v_b->setName("b");

  BasicBlock *basic_block =
      BasicBlock::Create(mod->getContext(), "entry", function);

  AllocaInst *alloca_a_addr = new AllocaInst(
      IntegerType::getInt32Ty(mod->getContext()), 4, "a.addr", basic_block);
  alloca_a_addr->setAlignment(4);
  AllocaInst *alloca_b_addr = new AllocaInst(
      IntegerType::getInt32Ty(mod->getContext()), 4, "a.addr", basic_block);
  alloca_b_addr->setAlignment(4);

  StoreInst *st0 = new StoreInst(v_a, alloca_a_addr, false, basic_block);
  st0->setAlignment(4);
  StoreInst *st1 = new StoreInst(v_b, alloca_b_addr, false, basic_block);
  st1->setAlignment(4);

  LoadInst *ld0 = new LoadInst(alloca_a_addr, "", false, basic_block);
  ld0->setAlignment(4);
  LoadInst *ld1 = new LoadInst(alloca_b_addr, "", false, basic_block);
  ld1->setAlignment(4);

  BinaryOperator *binary_operator = BinaryOperator::Create(
      Instruction::BinaryOps::Add, ld0, ld1, "add", basic_block);
  ReturnInst::Create(mod->getContext(), binary_operator, basic_block);

  return mod;
}

struct BasicPass : public FunctionPass {
  static char ID;

  explicit BasicPass() : FunctionPass(ID) {}

  bool doInitialization(Module &module) override {
    if (GlobalVariable *global_variable =
            module.getGlobalVariable("llvm.global.annotations")) {
      for (Value *v_meta : global_variable->operands()) {
        if (ConstantArray *constant_array = dyn_cast<ConstantArray>(v_meta)) {
          for (Value *v_operands : constant_array->operands()) {
            if (ConstantStruct *constant_struct =
                    dyn_cast<ConstantStruct>(v_operands)) {
              if (constant_struct->getNumOperands() >= 2) {
                if (GlobalVariable *global_ann = dyn_cast<GlobalVariable>(
                        constant_struct->getOperand(1)->getOperand(0))) {
                  if (ConstantDataArray *constant_data_array =
                          dyn_cast<ConstantDataArray>(
                              global_ann->getOperand(0))) {
                    StringRef annotation = constant_data_array->getAsString();
                    if (annotation.startswith("stuff")) {
                      llvm::outs() << "GOT ITTTTTTTTT\n";
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    return true;
  }

  enum struct DITypeNodeType
  {
    Unknown,
    Basic,
    Composite,
    Derived,
    Subroutine
  };

  struct DITypeNode
  {
    DITypeNodeType type_of_di_type = DITypeNodeType::Unknown;
    DIType* di_type = nullptr;
    std::vector<DITypeNode> children{};

    DITypeNode() = default;
    DITypeNode(DITypeNodeType type_of_di_type, DIType* di_type)
      : type_of_di_type(type_of_di_type),
        di_type(di_type) {
    }
  };

  //type tree
  struct DITypeTree
  {
    DITypeNode top_level_di_type_node{};
    std::string struct_name{};

    // template<typename Callback>
    // void iterate_tree(Callback callback)
    // {
    //   bool found_struct = false;
    //   iterate_tree_impl(top_level_di_type_node, callback, found_struct);
    // }

    template<typename Callback>
    void iterate_tree(Callback callback)
    {
      iterate_tree_impl(top_level_di_type_node, callback);
    }

    // template<typename Callback>
    // void iterate_tree_impl(DITypeNode& node, Callback callback, bool& top_struct_found)
    // {
    //   //TODO change this to check something else to end
    //   //cur
    //   if(node.type_of_di_type == DITypeNodeType::Composite)
    //   {
    //     callback(node.type_of_di_type, node.di_type);
    //     top_struct_found = true;
    //     return;
    //   }
    //   for(auto& child : node.children)
    //   {
    //     iterate_tree_impl(child, callback, top_struct_found);
    //     if(top_struct_found)
    //     {
    //       break;
    //     }
    //   }
    // }

    template<typename Callback>
    bool iterate_tree_impl(DITypeNode& node, Callback callback)
    {
      //TODO change this to check something else to end
      //if current element is a struct
      if(node.type_of_di_type == DITypeNodeType::Composite)
      {
        //iterate through children
        return callback(node.type_of_di_type, node.di_type);
      }

      //iterate through children
      for(auto& child : node.children)
      {
        //iterate through them to see if possibly struct
        if(!iterate_tree_impl(child, callback))
        {
          return false;
        }
      }
      return true;
    }
  };

  using DITypeParserCallback = std::function<void(DIType*)>;

  class DITypeParser
  {
  public:
    explicit DITypeParser(DIType* top_level_di_type)
      : top_level_di_type(top_level_di_type) {
    }

    DITypeTree parse_segment()
    {
      //setup tree
      DITypeTree tree;
      DITypeNode& top_level_di_type_node = tree.top_level_di_type_node;
      DITypeNode* di_type_node = &top_level_di_type_node;
      di_type_node->di_type = top_level_di_type;

      std::function<void(DITypeNode*)> populate_tree;
      populate_tree = [&populate_tree, &tree](DITypeNode* type_node) {
        DIType* di_type = type_node->di_type;
        if(!di_type->isResolved())
        {
          di_type->resolve();
        }
        if(DIBasicType* basic_type = dyn_cast<DIBasicType>(di_type))
        {
          type_node->type_of_di_type = DITypeNodeType::Basic;

          //TODO get rid of
          di_type = basic_type;
        }
        else if(DICompositeType* composite_type = dyn_cast<DICompositeType>(di_type))
        {
          //struct
          type_node->type_of_di_type = DITypeNodeType::Composite;

          //insert name first
          if(tree.struct_name.empty() && !composite_type->getName().empty())
          {
            tree.struct_name = composite_type->getName().data();
          }

          //iterate through struct
          for (DINode* di_sub_node : composite_type->getElements()) {
            if(DIType* di_sub_node_type = dyn_cast<DIType>(di_sub_node))
            {
              DITypeNode sub_node{ DITypeNodeType::Unknown, di_sub_node_type };
              populate_tree(&sub_node);
              type_node->children.emplace_back(std::move(sub_node));
            }
          }
        }
        else if(DIDerivedType* derived_type = dyn_cast<DIDerivedType>(di_type))
        {
          //pointers, etc
          type_node->type_of_di_type = DITypeNodeType::Derived;

          //a pointer can be a typedef to a struct
          if(tree.struct_name.empty())
          {
            if(derived_type->getTag() == dwarf::DW_TAG_typedef)
            {
              tree.struct_name = derived_type->getName().data();
            }
          }

          DIType* resolved_derived_type = derived_type->getBaseType().resolve();
          DITypeNode sub_node{ DITypeNodeType::Unknown, resolved_derived_type };
          populate_tree(&sub_node);
          type_node->children.emplace_back(std::move(sub_node));
        }
        else if(DISubroutineType* subroutine_type = dyn_cast<DISubroutineType>(di_type))
        {
          //function
          type_node->type_of_di_type = DITypeNodeType::Subroutine;

          //iterate through struct
          for (DITypeRef di_type_ref : subroutine_type->getTypeArray()) {
            DIType* resolved_type = di_type_ref.resolve();
            DITypeNode sub_node{ DITypeNodeType::Unknown, resolved_type };
            populate_tree(&sub_node);
            type_node->children.emplace_back(std::move(sub_node));
          }
        }
        else
        {
          //nothing
        }
      };

      populate_tree(di_type_node);
      return tree;
    }

  private:
    DIType* top_level_di_type;
  };

  //cache
  class DebugInfoCollector {
  public:
    std::map<std::string, DIType*> cache_types;
  };

  DebugInfoCollector debug_info_collector;
  
  class DebugInfoCollector2 {
  public:
    std::map<std::string, DITypeTree> cache_types;
  };

  DebugInfoCollector2 debug_info_collector2;

  void print_trace(Instruction& instruction) {
    const auto& basic_block = instruction.getParent();
    outs() << "instruction DUMP\n";
    instruction.dump();
    for (std::size_t i = 0; i < instruction.getNumOperands(); ++i) {
      const auto &operand = instruction.getOperand(i);
      Type *operand_type = operand->getType();
      operand->dump();
      operand_type->dump();

      if (PointerType *pointer_type = dyn_cast<PointerType>(operand_type)) {
        if (StructType *struct_type = dyn_cast<StructType>(pointer_type->getElementType())) {

          outs() << "IS POINTER\n";

          // pointer to struct
          const auto &cache_types = debug_info_collector.cache_types;

          SmallVector<StringRef, 10> struct_names;
          struct_type->getName().split(struct_names, ".");
          auto name_itr = std::find_if(struct_names.rbegin(), struct_names.rend(), [](const StringRef& str) { return !str.empty(); });
          std::string struct_name{};
          if(name_itr != struct_names.rend())
          {
            struct_name = name_itr->data();
          }

          outs() << struct_name << "\n";

          for(auto a : cache_types)
                outs() << a.first << "\n";

          std::map<std::string, DIType*>::const_iterator tree_const_iterator = cache_types.find(struct_name);
          if (tree_const_iterator != std::end(cache_types)) {

            // found type, now parse struct
            if (DICompositeType *di_struct_type = dyn_cast<DICompositeType>(tree_const_iterator->second)) {

              outs() << "FOUND TYPE\n";
              outs() << struct_type->getName() << '\n';

              IRBuilder<> ir_builder(&instruction);

              //check if printf is avaliable
              const auto &mod = basic_block->getModule();
              Function *printf_function = mod->getFunction("printf");
              if (!printf_function) {
                PointerType *Pty = PointerType::
                  get(IntegerType::get(mod->getContext(), 8), 0);
                FunctionType *FuncTy9 = FunctionType::
                  get(IntegerType::get(mod->getContext(), 32), true);

                printf_function = Function::Create(FuncTy9,
                                                   GlobalValue::
                                                   ExternalLinkage,
                                                   "printf", mod);
                printf_function->setCallingConv(CallingConv::C);

                printf_function->setAttributes(AttributeList{});
              }

              int num_member_elements = di_struct_type->getElements().size();

              std::string format_string;
              for(int i = 0; i < num_member_elements; i++)
              {
                format_string += "%s,%d,";
              }
              Value *format_string_value = ir_builder.
                CreateGlobalStringPtr(format_string);

              std::vector<Value*> arguments{format_string_value};
              arguments.reserve(di_struct_type->getElements().size() * 2 + 1);
              for (int i = 0; i < di_struct_type->getElements().size(); i++) {
                DINode *element = di_struct_type->getElements()[i];
                if (DIDerivedType *di_derived = dyn_cast<DIDerivedType>(element)) {
                  arguments.emplace_back(ir_builder.CreateGlobalStringPtr(di_derived->getName()));

                  std::vector<Value*> indices{ ConstantInt::get(basic_block->getContext(), APInt(32, 0)), ConstantInt::get(basic_block->getContext(), APInt(32, i))};
                  Value* struct_value = ir_builder.CreateGEP(struct_type, operand, indices);
                  LoadInst* loaded_struct_value = ir_builder.CreateLoad(struct_value);
                  arguments.emplace_back(loaded_struct_value);
                }
              }
              ir_builder.CreateCall(printf_function, arguments, "call");
            }
          }
        }
      
      }
    }
  }

  void print_trace2(Instruction& instruction)
  {
    const auto& basic_block = instruction.getParent();
    outs() << "instruction DUMP\n";
    instruction.dump();

    //if(instruction.getOpcode() != Instruction::MemoryOps::Store)
    //{
    //  return;
    //}
    for (std::size_t i = 0; i < instruction.getNumOperands(); ++i) {
      const auto &operand = instruction.getOperand(i);

      Type *operand_type = operand->getType();
      operand->dump();
      operand_type->dump();

      auto &cache_types = debug_info_collector2.cache_types;

      //recurse on pointer until arrive at struct
      Type *type = operand_type;
      std::size_t num_pointer_deferences = 0;
      while (PointerType *pointer_type = dyn_cast<PointerType>(type)) {
        type = pointer_type->getElementType();
        num_pointer_deferences++;
      }

      //if arrived type is a struct
      if (StructType *struct_type = dyn_cast<StructType>(type)) {

        //have to parse the type name (format is struct.Foo << want to get Foo)
        //assume less than 10 periods...
        SmallVector<StringRef, 10> struct_names;
        struct_type->getName().split(struct_names, ".");

        //go up to first string that isn't empty
        auto struct_name_itr = std::find_if(struct_names.rbegin(), struct_names.rend(),
                                     [](const StringRef &str)
                                     {
                                       return !str.empty();
                                     });
        StringRef struct_name;
        if (struct_name_itr != struct_names.rend()) {
          struct_name = struct_name_itr->data();
        }

        auto found_itr = cache_types.find(struct_name);
        if (found_itr != std::end(cache_types)) 
        {
          DITypeTree tree = found_itr->second;
          outs() << "NAME: " << struct_name << "\n";

          //print out after we edit to get next node :)
          IRBuilder<> ir_builder(instruction.getNextNode());

          //check if printf is avaliable
          const auto &mod = basic_block->getModule();
          Function *printf_function = mod->getFunction("printf");
          if (!printf_function) {
            FunctionType *FuncTy9 = FunctionType::
              get(IntegerType::get(mod->getContext(), 32), true);

            printf_function = Function::Create(FuncTy9,
                                               GlobalValue::
                                               ExternalLinkage,
                                               "printf", mod);
            printf_function->setCallingConv(CallingConv::C);

            printf_function->setAttributes(AttributeList{});
          }

          //set of structs already iterated through
          std::set<std::string> self_referencing{struct_name};

          //print struct type and variable name
          Value *struct_type_string = ir_builder.CreateGlobalStringPtr(struct_name);
          Value *struct_name_string = ir_builder.CreateGlobalStringPtr(operand->getName());
          std::vector<Value*> struct_arguments{ir_builder.CreateGlobalStringPtr("%s %s\n"), struct_type_string, struct_name_string};

          ir_builder.CreateCall(printf_function, struct_arguments, "call");

          tree.iterate_tree([&](DITypeNodeType& node_type, DIType* di_type)
          {
            switch(node_type)
            {
            case DITypeNodeType::Unknown:
            {
              EXIT_WITH_MESSAGE("Reached an impossible node");
              break;
            }
            case DITypeNodeType::Basic: 
            {
              DIBasicType* basic_type = cast<DIBasicType>(di_type);
              //ignore for now
              break;
            }
            case DITypeNodeType::Composite:
            {
              DICompositeType* composite_type = cast<DICompositeType>(di_type);

              if(composite_type->getTag() == dwarf::DW_TAG_structure_type)
              {
                //create a load for each pointer to struct we want
                //TODO reference struct in struct (doesn't work for that)
                Value* pointer_to_struct = operand;
                for(std::size_t i = 0; i < num_pointer_deferences - 1; i++)
                {
                  pointer_to_struct = ir_builder.CreateLoad(pointer_to_struct);
                }

                const unsigned num_member_elements = composite_type->getElements().size();

                //create format string
                std::string format_string;
                for(auto i = 0; i < num_member_elements; i++)
                {
                  format_string += "%s,%d,";
                }
                format_string += "\n";

                Value *format_string_value = ir_builder.CreateGlobalStringPtr(format_string);

                //populate arguments for format string
                std::vector<Value*> arguments{format_string_value};
                arguments.reserve(composite_type->getElements().size() * 2 + 1);

                //loop through all arguments
                for (int i = 0; i < composite_type->getElements().size(); i++) {
                  DINode *element = composite_type->getElements()[i];

                  //check if derived (to member)
                  if (DIDerivedType *di_derived = dyn_cast<DIDerivedType>(element)) {
                    //check if is member
                    if(di_derived->getTag() == dwarf::DW_TAG_member)
                    {
                      //check if is self referencing
                      llvm::outs() << "AAA" << di_derived->getBaseType().resolve()->getName() << " " << struct_name
                        << "\n";

                      if(struct_name == di_derived->getBaseType().resolve()->getName())
                      {
                        //TODO create loop until null, if pointer
                        //for now, print same thing
                        llvm::outs() << "SELF REFERENCING\n";
                      }

                      arguments.emplace_back(ir_builder.CreateGlobalStringPtr(di_derived->getName()));

                      //get correct offset to struct member
                      std::vector<Value*> indices{ ConstantInt::get(basic_block->getContext(), APInt(32, 0)), ConstantInt::get(basic_block->getContext(), APInt(32, i))};

                      //GEP to get struct member
                      Value* struct_value = ir_builder.CreateGEP(struct_type, pointer_to_struct, indices);

                      //load the struct member value
                      LoadInst* loaded_struct_value = ir_builder.CreateLoad(struct_value);

                      //place into arguments
                      arguments.emplace_back(loaded_struct_value); 
                    }
                    else
                    {
                      EXIT_WITH_MESSAGE("Reached an impossible node");
                    }
                  }
                }
                //create call
                ir_builder.CreateCall(printf_function, arguments, "call");
              }
              break;
            }
            case DITypeNodeType::Derived: 
            {
              DIDerivedType* derived_type = cast<DIDerivedType>(di_type);

              //struct member
              if(derived_type->getTag() == dwarf::DW_TAG_member)
              {
                //derived_type->getConstant()
              }
              break;
            }
            case DITypeNodeType::Subroutine:
            {
              DISubroutineType* subroutine_type = cast<DISubroutineType>(di_type);
              break;
            }
            default: 
            { 
                EXIT_WITH_MESSAGE("Reached an impossible node");
            }
            }
            return true;
          });
        }
      }
    }
  }

  void print_trace3(Instruction& instruction)
  {
    //recursive iteration to find first load to struct
    std::vector<Instruction*> struct_element_chain;

    //next expected instruction to place builder
    Instruction* instruction_to_build_on = instruction.getNextNode();

    //iterate until hit instruction that is not load/GEP, which should be alloca
    std::function<void(Instruction*)> recurse_until_base;
    recurse_until_base = [&recurse_until_base, &struct_element_chain, &instruction_to_build_on](Instruction* this_instruction)
    {
      //catch load instruction
      if(LoadInst* load_inst = dyn_cast<LoadInst>(this_instruction))
      {
        if(Instruction* pointer_operand = dyn_cast<Instruction>(load_inst->getPointerOperand()))
        {
          //add this instruction to chain
          struct_element_chain.emplace_back(pointer_operand);
          recurse_until_base(pointer_operand);          
        }
      }
      //catch GEP instructions
      else if(GetElementPtrInst* GEPInst = dyn_cast<GetElementPtrInst>(this_instruction))
      {
        if(Instruction* pointer_operand = dyn_cast<Instruction>(GEPInst->getPointerOperand()))
        {
          //add this instruction to chain
          struct_element_chain.emplace_back(pointer_operand);
          recurse_until_base(pointer_operand);          
        }
      }
      else if(AllocaInst* alloca_inst = dyn_cast<AllocaInst>(this_instruction))
      {
        //do nothing, this is top level
      }
      else if(CallInst* call_inst = dyn_cast<CallInst>(this_instruction))
      {
        //do nothing, this is top level
        const StringRef called_function = call_inst->getCalledFunction()->getName();
      
        //check if malloc/free
        if(called_function == "malloc")
        {
          //have to go forward and get store

          //expect bitcast and then store
          for(Value* user : this_instruction->users())
          {
            if(BitCastInst* bit_cast_inst = dyn_cast<BitCastInst>(user))
            {
              for(Value* bit_cast_user : bit_cast_inst->users())
              {
                if(StoreInst* store_inst = dyn_cast<StoreInst>(bit_cast_user))
                {
                  //remove all elements
                  struct_element_chain.clear();

                  //instruction should be good to use at this point
                  instruction_to_build_on = store_inst->getNextNode();

                  //add store instruction
                  struct_element_chain.emplace_back(store_inst);

                  //restore call entry after store instruction
                  struct_element_chain.emplace_back(this_instruction);

                  if(Instruction* pointer_operand = dyn_cast<Instruction>(store_inst->getPointerOperand()))
                  {
                    //add to chain
                    struct_element_chain.emplace_back(pointer_operand);

                    //recurse
                    recurse_until_base(pointer_operand);
                  }

                  return;
                }
              }
            }
          }
        }
        else if(called_function == "free")
        {
          //first argument is operand
          if(call_inst->getNumArgOperands() == 1)
          {
            //return value is operand
            if(Instruction* pointer_operand = dyn_cast<Instruction>(call_inst->getArgOperand(0)))
            {
              recurse_until_base(pointer_operand);
            }
          } 
          else
          {
            EXIT_WITH_MESSAGE("Free should have only one argument\n");
          }
        }
      }
      else if(BitCastInst* bit_cast_inst = dyn_cast<BitCastInst>(this_instruction))
      {
        //first argument is operand
        if(bit_cast_inst->getNumOperands() == 1)
        {
          //return value is operand
          if(Instruction* pointer_operand = dyn_cast<Instruction>(bit_cast_inst->getOperand(0)))
          {
            //add to chain
            struct_element_chain.emplace_back(pointer_operand);
            recurse_until_base(pointer_operand);
          }
        } 
        else
        {
          EXIT_WITH_MESSAGE("Free should have only one argument\n");
        }
      }
      else
      {
        //should never happen since iterating through all the deferences
        for(Value* v : struct_element_chain)
        {
          v->dump();
        }
        this_instruction->dump();
        EXIT_WITH_MESSAGE("While looping to find base struct, encountered bad instruction\n");
      }
      //iterate through use because they're the values that this value depends on, (use)
      //not this value depending on this value (aka an add with this value as a parameter)
    };

    //block
    const auto& basic_block = instruction.getParent();
    //outs() << "instruction DUMP\n";
    //instruction.dump();

    //TODO malloc/free
    Value* pointer_operand = nullptr;

    if(StoreInst* store_inst = dyn_cast<StoreInst>(&instruction))
    {
      //place this instruction in the chain
      struct_element_chain.emplace_back(&instruction);

      pointer_operand = store_inst->getPointerOperand();
    }
    else if(CallInst* call_inst = dyn_cast<CallInst>(&instruction)) 
    {
      const StringRef called_function = call_inst->getCalledFunction()->getName();
      
      //check if malloc/free
      if(called_function == "malloc" || called_function == "free")
      {
        //return value is operand
        //set function to start as free
        pointer_operand = call_inst;
      }
    }
    else if(IntrinsicInst* instrinstic_inst = dyn_cast<IntrinsicInst>(&instruction))
    {
      //todo memcpy..., etc
    }

    //return if instruction isn't a store or call
    if(pointer_operand == nullptr)
    {
      return;
    }

    //pointer operand itself is an instruction
    if(Instruction* operand_instruction = dyn_cast<Instruction>(pointer_operand))
    {
      //place this operand instruction into the chain as well
      struct_element_chain.emplace_back(operand_instruction);

      //now recurse until base class
      recurse_until_base(operand_instruction);
    }
    else
    {
      EXIT_WITH_MESSAGE("Store pointer operand is not an instruction -- Must be an instruction\n");
    }

    //reverse the instructions, cause iterated from last instruction to first (which should be alloca)
    std::reverse(std::begin(struct_element_chain), std::end(struct_element_chain));

    //ex
    /*
     %addr_s2 = alloca %struct.Stuff**, align 8
     %3 = load %struct.Stuff**, %struct.Stuff*** %addr_s2, align 8, !dbg !40
     %4 = load %struct.Stuff*, %struct.Stuff** %3, align 8, !dbg !41
     %one3 = getelementptr inbounds %struct.Stuff, %struct.Stuff* %4, i32 0, i32 0, !dbg !42
     store i32 1, i32* %one3, align 8, !dbg !43
     */

    //first instruction should be alloca... 
    Instruction* struct_instruction = struct_element_chain[0];

    //recurse on pointer until arrive at struct
    Type *struct_instruction_type = struct_instruction->getType();
    std::size_t num_pointer_deferences = 0;
    while (PointerType *pointer_type = dyn_cast<PointerType>(struct_instruction_type)) {
      struct_instruction_type = pointer_type->getElementType();
      num_pointer_deferences++;
    }

    //if arrived type is a struct (which definitely should be since first is alloca)
    if (StructType *struct_type = dyn_cast<StructType>(struct_instruction_type)) {

      //have to parse the type name (format is struct.Foo << want to get Foo)
      //assume less than 10 periods...
      SmallVector<StringRef, 10> struct_names;
      struct_type->getName().split(struct_names, ".");

      //go up to first string that isn't empty
      auto struct_name_itr = std::find_if(struct_names.rbegin(), struct_names.rend(),
                                   [](const StringRef &str)
                                   {
                                     return !str.empty();
                                   });

      llvm::outs() << "YES:" << *struct_name_itr << "\n";;

      //check if printf is avaliable
      const auto &mod = basic_block->getModule();
      Function *printf_function = mod->getFunction("printf");
      if (!printf_function) {
        FunctionType *FuncTy9 = FunctionType::
          get(IntegerType::get(mod->getContext(), 32), true);

        printf_function = Function::Create(FuncTy9,
                                           GlobalValue::
                                           ExternalLinkage,
                                           "printf", mod);
        printf_function->setCallingConv(CallingConv::C);

        printf_function->setAttributes(AttributeList{});
      }

      //print out after we edit to get next node :)
      IRBuilder<> ir_builder(instruction_to_build_on);

      //prepare arguments
      std::vector<Value*> arguments{};

      std::stringstream format_string;
      format_string << "\n";

      //create header
      format_string << "HEADER:";

      //print out debug info: filename, the function, line
      MDNode* md_node = instruction.getMetadata("dbg");
      if(md_node)
      {
        if(DILocation* debug_location = dyn_cast<DILocation>(md_node))
        {
          const std::string filename = debug_location->getFilename().str();
          const std::string function_name = basic_block->getParent()->getName().str();
          const unsigned line_no = debug_location->getLine();
          format_string << filename << "-"
                      << function_name << "-"
                      << line_no << ":";
        }
        else
        {
          EXIT_WITH_MESSAGE("Expecting debug information to be compiled\n");
        } 
      } 
      else 
      {
        const std::string function_name = basic_block->getParent()->getName().str();
        format_string << "NULL" << "-"
                    << function_name << "-"
                    << "NULL" << ":";
      } 

      DICompositeType* composite_type = nullptr;

      //get information about struct
      if (const DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(&instruction))
      {
        //local variable
        DILocalVariable *di_local_variable = DDI->getVariable();
        DIType *di_type = di_local_variable->getType().resolve();

        //recurse until we reach a composite type
        while(DIDerivedType* derived_type = dyn_cast<DIDerivedType>(di_type))
        {
          llvm::outs() << "GOT TYPE\n";
          di_type = derived_type->getBaseType().resolve();
        }

        //must be composite type
        if(composite_type = dyn_cast<DICompositeType>(di_type))
        {
          llvm::outs() << "GOT COMPOSITE\n";

        }
      }

      //TODO hacky, pointer value is stored pointer value, instead of int
      Value* stored_pointer_value = nullptr;
      std::vector<Value*> load_variables;

      //iterate through all instructions and construct printf to send
      for(Instruction* i : struct_element_chain)
      {
        i->dump();

        if(AllocaInst* alloca_inst = dyn_cast<AllocaInst>(i)) 
        {
          //must be first instruction

          //TODO stack address
          //get the address first???

          //print out struct type and name
          format_string << struct_name_itr->str() << std::string(num_pointer_deferences, '*') << "-"
                      << alloca_inst->getName().str() << "-";

          format_string << "%p:";
          load_variables.emplace_back(alloca_inst);
        }
        else if(LoadInst* load_inst = dyn_cast<LoadInst>(i))
        {
          //print out * for deference
          format_string << "*-";

          format_string << "%p-";
          
          std::vector<Value*> indices{ ConstantInt::get(basic_block->getContext(), APInt(32, 0)), ConstantInt::get(basic_block->getContext(), APInt(32, 0))};
          auto* struct_value = ir_builder.CreateGEP(struct_type, load_inst, indices);

          load_variables.emplace_back(struct_value);
        }
        else if(GetElementPtrInst* GEPInst = dyn_cast<GetElementPtrInst>(i))
        {
          std::vector<int> indices{};

          //get operands
          for(size_t i = 0; i < GEPInst->getNumIndices(); i++)
          {
            if(ConstantInt* index = dyn_cast<ConstantInt>(GEPInst->getOperand(i + 1)))
            {
              //first has to be 0
              if(!i && index->getZExtValue())
              {
                EXIT_WITH_MESSAGE("First index of GEP is 0, should not happen");
              }
              indices.emplace_back(index->getZExtValue());
            }
          }

          //print out values
          //std::copy(std::begin(indices), std::end(indices), std::ostream_iterator<int>(llvm::outs, ":"));
          format_string << "GEP-";
          for(const auto& index : indices)
          {
            format_string << std::hex << index << "-";
          }

          if(composite_type != nullptr)
          {
            DIType *di_type = nullptr;
            auto elements = composite_type->getElements();

            //skip first index
            for(int i = 1; i < indices.size(); i++)
            {
              const auto& index = indices[i];
              if(index > elements.size())
              {
                //well, shouldn't happen
                EXIT_WITH_MESSAGE("Indices is greater than element size")
              }
              auto di_node = elements[index];
              if(di_type = dyn_cast<DIType>(di_node))
              {
                if(DIDerivedType* derived_type = dyn_cast<DIDerivedType>(di_type))
                {
                  if(derived_type->getTag() == dwarf::DW_TAG_member)
                  {
                    format_string << "GEPDONE-" << derived_type->getName().data() << "-";
                  }
                  //need to iterate even more for bigger underlying structs...

                  di_type = derived_type->getBaseType().resolve();
                }
              }
            }
          }
        }
        else if(StoreInst* store_inst = dyn_cast<StoreInst>(i))
        {
          //this must be the last instruction!!!
          if(ConstantInt* constant_int = dyn_cast<ConstantInt>(store_inst->getValueOperand()))
          {
            format_string << "s-" << constant_int->getZExtValue();
          } 
          else
          {
            //form pointer value
            format_string << "s-";
            format_string << "%p";
            //std::vector<Value*> indices{ ConstantInt::get(basic_block->getContext(), APInt(32, 0))};

            Value* store_operand = store_inst->getValueOperand();
            stored_pointer_value = store_operand;//ir_builder.CreateGEP(store_operand->getType(), store_operand, indices);
          }
        }
        else if(CallInst* call_inst = dyn_cast<CallInst>(i)) 
        {
          const StringRef called_function = call_inst->getCalledFunction()->getName();

          //check if malloc/free
          if(called_function == "malloc")
          {
            format_string << "m-";
          }
          else if(called_function == "free")
          {
            //first argument is operand
            if(call_inst->getNumArgOperands() == 1)
            {
              //form pointer value like store
              format_string << "f-";
              format_string << "%p";

              //argument of free
              stored_pointer_value = call_inst->getArgOperand(0);
            }
            else
            {
              EXIT_WITH_MESSAGE("Free should have only one argument\n");
            }
          }
        }
        else
        {
          llvm::errs() << "=========\n";
          for(Value* v : struct_element_chain)
          {
            v->dump();            
          }
          EXIT_WITH_MESSAGE("Unknown instruction in list -- must only be load, gep, store, malloc, free, bitcast\n");
        }
      }

      //end format string
      format_string << "\n";

      //create format string value
      Value* format_string_value = ir_builder.CreateGlobalStringPtr(format_string.str());

      //put as argument
      arguments.emplace_back(format_string_value);

      arguments.insert(std::end(arguments), std::begin(load_variables), std::end(load_variables));
      
      if (stored_pointer_value) 
      {
        arguments.emplace_back(stored_pointer_value);
      }

      //form arguments
      ir_builder.CreateCall(printf_function, arguments);

      llvm::outs() << "END\n";
    }
    else
    {
      //TODO handle ints
      return;
      struct_instruction_type->dump();
      struct_instruction->dump();
      EXIT_WITH_MESSAGE("First instruction should be alloca\n");
    }
  }

  /*
   * Runs on each function
   */

  bool runOnFunction(Function &function) override {
    llvm::outs() << "FUNCTION: " << function.getName() << "\n";

    for (auto &basic_block : function) {
      std::vector<Value *> integers;
      for (auto &instruction : basic_block) {
        //check if is @dbg.declare attribute
        if (const DbgDeclareInst *DDI = dyn_cast<DbgDeclareInst>(&instruction)) 
        {
          //local variable
          DILocalVariable *di_local_variable = DDI->getVariable();
          DIType *di_type = di_local_variable->getType().resolve();

          //iterate pointer until base type
          
          // if (DIDerivedType *di_derived1 = dyn_cast<DIDerivedType>(di_type)) {
          //   if (DIDerivedType *di_derived2 = dyn_cast<DIDerivedType>(di_derived1->getBaseType().resolve())) {
          //     if (DICompositeType *di_composite = dyn_cast<DICompositeType>(di_derived2->getBaseType().resolve())) {
          //       debug_info_collector.cache_types.insert( {di_derived2->getName().data(), di_composite} );
          //     }
          //   }
          // }

          DITypeParser di_type_parser(di_type);
          DITypeTree tree = di_type_parser.parse_segment();
          debug_info_collector2.cache_types.insert({tree.struct_name, tree});
          outs() << "STRUCTNAME: " << tree.struct_name << "\n";
        }
      }
      //second run (actually print out data)
      for (auto &instruction : basic_block) {
        //print_trace(instruction);
        print_trace3(instruction);
      }
    }
    
    return true;
  }
};

char BasicPass::ID = 0;

static RegisterPass<BasicPass> register_pass("memory-tracer",
                                             "basic memory tracer");

// register pass for clang use
void registerMyPassPass(const PassManagerBuilder & a, legacy::PassManagerBase &PM) {
  PM.add(new BasicPass());
}

static RegisterStandardPasses RegisterMBAPass(PassManagerBuilder::EP_EarlyAsPossible, registerMyPassPass);
