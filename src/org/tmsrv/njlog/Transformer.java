package org.tmsrv.njlog;

import java.io.*;
import java.util.*;

import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.util.*;


public class Transformer {
	private Rules rules;


	public Transformer(Rules rules) {
		this.rules = rules;
	}


	public byte [] transform(byte [] clazz) throws Exception {
/*		if (rules.isDebug()) {
			Printer printer1 = new Printer(
				new PrintWriter(
					src.replaceAll("/", ".") + ".in"
				)
			);
			Printer printer2 = new Printer(
				new PrintWriter(
					src.replaceAll("/", ".") + ".out"
				)
			);
			byte [] data;

			printer1.print(new FileInputStream(src));
			printer1.close();

			log.info(src + " -> " + dst);
			data = Transformer.transform(new FileInputStream(src), packages);
			log.info(" done.");

			printer2.print(data);
			printer2.close();
		}*/

		return transform(
			new ByteArrayInputStream(clazz)
		);
	}

	private byte [] transform(InputStream clazz) throws Exception {
		ClassReader cr = new ClassReader(clazz);
		ClassWriter cw = new TransformerClassWriter(cr, rules);

		// return transformed class bytes
		cr.accept(new ClassAdapter(cw), 0);

		return cw.toByteArray();
	}


	private static void info(Object o) {
		System.out.println(o.toString());
	}

	private static void debug1(Object o) {
		System.err.println(o.toString());
	}

	private static void debug2(Object o) {
		System.err.println("	" + o.toString());
	}

	private static void debug3(Object o) {
		System.err.println("		" + o.toString());
	}


	private static class TransformerClassWriter extends ClassWriter {
		private ClassReader cr;

		private Rules rules;

//		private List<FieldNode> fields = new LinkedList<FieldNode>();


		public TransformerClassWriter(ClassReader cr, Rules rules) {
			super(0);
			this.cr = cr;
			this.rules = rules;
		}


/*		protected boolean skipField(String owner, String name, String desc) {
			for (FieldNode field : fields) {
				if (field.name.equals(name) && field.desc.equals(desc)) {
					return true;
				}
			}
			return false;
		}*/


		@Override
		public FieldVisitor visitField(int access, String name, String desc, String signature, Object value) {
			return super.visitField(access, name, desc, signature, value);
		}

		@Override
		public MethodVisitor visitMethod(int access, final String name, String desc, String signature, String[] exceptions) {
			if (rules.isDebug()) {
				debug1(cr.getClassName() + "." + name);
			}
			return new TransformerMethodAdapter(
				super.visitMethod(access, name, desc, signature, exceptions),
				rules,
				cr.getClassName() + "." + name
			) {
				@Override
				public void visitMaxs(int maxStack, int maxLocals) {
					// write any pending nodes
					write(mv);

					super.visitMaxs(maxStack, maxLocals);
				}

				@Override
				public void visitFieldInsn(int opcode, String owner, String name, String desc) {
					add(
						new FieldInsnNode(opcode, owner, name, desc)
					);
				}

				@Override
				public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] stack) {
					add(
						new FrameNode(type, nLocal, local, nStack, stack)
					);
				}

				@Override
				public void visitIincInsn(int var, int increment) {
					add(
						new IincInsnNode(var, increment)
					);
				}

				@Override
				public void visitIntInsn(int opcode, int operand) {
					add(
						new IntInsnNode(opcode, operand)
					);
				}

				@Override
				public void visitInsn(int opcode) {
					add(
						new InsnNode(opcode)
					);
				}

				@Override
				public void visitJumpInsn(int opcode, Label label) {
					add(
						new JumpInsnNode(opcode, new LabelNode(label))
					);
				}

				@Override
				public void visitLabel(Label label) {
					add(
						new LabelNode(label)
					);
				}

				@Override
				public void visitLdcInsn(Object cst) {
					add(
						new LdcInsnNode(cst)
					);
				}

				@Override
				public void visitLineNumber(int line, Label start) {
					// skip
				}

				@Override
				public void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index) {
					super.visitLocalVariable(name, desc, signature, start, end, index);
				}

				@Override
				public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
					LabelNode [] labelNodes = new LabelNode[labels.length];

					for (int i = 0; i < labels.length; i++) {
						labelNodes[i] = new LabelNode(labels[i]);
					}
					add(
						new LookupSwitchInsnNode(new LabelNode(dflt), keys, labelNodes)
					);
				}

				@Override
				public void visitMethodInsn(int opcode, String owner, String name, String desc) {
					add(
						new MethodInsnNode(opcode, owner, name, desc)
					);
				}

				@Override
				public void visitMultiANewArrayInsn(String desc, int dims) {
					add(
						new MultiANewArrayInsnNode(desc, dims)
					);
				}

				@Override
				public void visitTableSwitchInsn(int min, int max, Label dflt, Label[] labels) {
					LabelNode [] labelNodes = new LabelNode[labels.length];

					for (int i = 0; i < labels.length; i++) {
						labelNodes[i] = new LabelNode(labels[i]);
					}
					add(
						new TableSwitchInsnNode(min, max, new LabelNode(dflt), labelNodes)
					);
				}

				@Override
				public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
					add(
						new TryCatchBlockNode(new LabelNode(start), new LabelNode(end), new LabelNode(handler), type)
					);

					super.visitTryCatchBlock(start, end, handler, type);
				}

				@Override
				public void visitTypeInsn(int opcode, String type) {
					add(
						new TypeInsnNode(opcode, type)
					);
				}

				@Override
				public void visitVarInsn(int opcode, int var) {
					add(
						new VarInsnNode(opcode, var)
					);
				}
			};
		}
	};

	private static class TransformerMethodAdapter extends MethodAdapter {
		public Rules rules;

		public String scope;

		public int level;

		public LinkedList<N> children = new LinkedList<N>();

		public LinkedList<TryCatchBlockNode> blocks = new LinkedList<TryCatchBlockNode>();

		public Map<Label, Integer> labels = new HashMap<Label, Integer>();


		public TransformerMethodAdapter(MethodVisitor mv, Rules rules, String scope) {
			super(mv);
			this.rules = rules;
			this.scope = scope;
			this.level = 0;
		}


		public void add(FieldInsnNode child) {
			Type type = Type.getType(child.desc);

			switch (child.getOpcode()) {
			case Opcodes.GETFIELD:
				level += type.getSize() - 1;
				break;

			case Opcodes.GETSTATIC:
				level += type.getSize();
				break;

			case Opcodes.PUTFIELD:
				level -= 1 + type.getSize();
				break;

			case Opcodes.PUTSTATIC:
				level -= type.getSize();
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(FrameNode child) {
			if (rules.isDebug()) {
				debug2("FRAME:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(IincInsnNode child) {
			if (rules.isDebug()) {
				debug2("IINC:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(IntInsnNode child) {
			switch (child.getOpcode()) {
			case Opcodes.BIPUSH:
				level++;
				break;

			case Opcodes.SIPUSH:
				level++;
				break;

			case Opcodes.NEWARRAY:
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(InsnNode child) {
			switch (child.getOpcode()) {
			case Opcodes.NOP:
				break;

			case Opcodes.ACONST_NULL:
			case Opcodes.ICONST_M1:
			case Opcodes.ICONST_0:
			case Opcodes.ICONST_1:
			case Opcodes.ICONST_2:
			case Opcodes.ICONST_3:
			case Opcodes.ICONST_4:
			case Opcodes.ICONST_5:
			case Opcodes.FCONST_0:
			case Opcodes.FCONST_1:
			case Opcodes.FCONST_2:
				level++;
				break;
			case Opcodes.LCONST_0:
			case Opcodes.LCONST_1:
			case Opcodes.DCONST_0:
			case Opcodes.DCONST_1:
				level += 2;
				break;

			case Opcodes.IALOAD:
			case Opcodes.FALOAD:
			case Opcodes.AALOAD:
			case Opcodes.BALOAD:
			case Opcodes.CALOAD:
			case Opcodes.SALOAD:
				level--;
				break;
			case Opcodes.LALOAD:
			case Opcodes.DALOAD:
				break;

			case Opcodes.IASTORE:
			case Opcodes.FASTORE:
			case Opcodes.AASTORE:
			case Opcodes.BASTORE:
			case Opcodes.CASTORE:
			case Opcodes.SASTORE:
				level -= 3;
				break;
			case Opcodes.LASTORE:
			case Opcodes.DASTORE:
				level -= 4;
				break;

			case Opcodes.POP:
				level--;
				break;
			case Opcodes.POP2:
				level -= 2;
				break;

			case Opcodes.DUP:
			case Opcodes.DUP_X1:
			case Opcodes.DUP_X2:
				level++;
				break;
			case Opcodes.DUP2:
			case Opcodes.DUP2_X1:
			case Opcodes.DUP2_X2:
				level += 2;
				break;
			case Opcodes.SWAP:
				break;

			case Opcodes.IADD:
			case Opcodes.FADD:
			case Opcodes.ISUB:
			case Opcodes.FSUB:
			case Opcodes.IMUL:
			case Opcodes.FMUL:
			case Opcodes.IDIV:
			case Opcodes.FDIV:
			case Opcodes.IREM:
			case Opcodes.FREM:
			case Opcodes.ISHL:
			case Opcodes.LSHL:
			case Opcodes.ISHR:
			case Opcodes.LSHR:
			case Opcodes.IUSHR:
			case Opcodes.LUSHR:
			case Opcodes.IAND:
			case Opcodes.IOR:
			case Opcodes.IXOR:
				level--;
				break;
			case Opcodes.LADD:
			case Opcodes.DADD:
			case Opcodes.LSUB:
			case Opcodes.DSUB:
			case Opcodes.LMUL:
			case Opcodes.DMUL:
			case Opcodes.LDIV:
			case Opcodes.DDIV:
			case Opcodes.LREM:
			case Opcodes.DREM:
			case Opcodes.LAND:
			case Opcodes.LOR:
			case Opcodes.LXOR:
				level -= 2;
				break;

			case Opcodes.INEG:
			case Opcodes.LNEG:
			case Opcodes.FNEG:
			case Opcodes.DNEG:
				break;

			case Opcodes.I2L:
			case Opcodes.I2D:
			case Opcodes.F2L:
			case Opcodes.F2D:
				level++;
				break;

			case Opcodes.L2I:
			case Opcodes.L2F:
			case Opcodes.D2I:
			case Opcodes.D2F:
				level--;
				break;

			case Opcodes.I2F:
			case Opcodes.F2I:
			case Opcodes.L2D:
			case Opcodes.D2L:
			case Opcodes.I2B:
			case Opcodes.I2C:
			case Opcodes.I2S:
				break;

			case Opcodes.LCMP:
				level -= 3;
				break;

			case Opcodes.FCMPL:
			case Opcodes.FCMPG:
				level--;
				break;

			case Opcodes.DCMPL:
			case Opcodes.DCMPG:
				level -= 3;
				break;

			case Opcodes.IRETURN:
			case Opcodes.FRETURN:
			case Opcodes.ARETURN:
				level--;
				if (level != 0) {
					throw new RuntimeException(scope + ": return but level is " + level);
				} else {
					break;
				}

			case Opcodes.LRETURN:
			case Opcodes.DRETURN:
				level -= 2;
				if (level != 0) {
					throw new RuntimeException(scope + ": return but level is " + level);
				} else {
					break;
				}

			case Opcodes.RETURN:
				if (level != 0) {
					throw new RuntimeException(scope + ": return but level is " + level);
				} else {
					break;
				}

			case Opcodes.ARRAYLENGTH:
				break;

			case Opcodes.ATHROW:
				level--;
				break;

			case Opcodes.MONITORENTER:
			case Opcodes.MONITOREXIT:
				level--;
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(JumpInsnNode child) {
			switch (child.getOpcode()) {
			case Opcodes.IFEQ:
			case Opcodes.IFNE:
			case Opcodes.IFLT:
			case Opcodes.IFGE:
			case Opcodes.IFGT:
			case Opcodes.IFLE:
				level--;
				break;

			case Opcodes.IF_ICMPEQ:
			case Opcodes.IF_ICMPNE:
			case Opcodes.IF_ICMPGE:
			case Opcodes.IF_ICMPGT:
			case Opcodes.IF_ICMPLE:
			case Opcodes.IF_ICMPLT:
			case Opcodes.IF_ACMPEQ:
			case Opcodes.IF_ACMPNE:
				level -= 2;
				break;

			case Opcodes.GOTO:
				break;

			case Opcodes.JSR:
				level++;
				break;

			case Opcodes.IFNULL:
			case Opcodes.IFNONNULL:
				level--;
				break;

			default:
				throw new RuntimeException("[" + child.getOpcode() + "]");
			}

			if (labels.containsKey(child.label.getLabel())) {
				int prevLevel = labels.get(child.label.getLabel());

				if (prevLevel != level) {
					throw new RuntimeException(scope + ": jump but level is " + level + " and previous is " + prevLevel);
				}
			} else {
				labels.put(child.label.getLabel(), level);
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(LabelNode child) {
			Integer jumpLevel = labels.get(child.getLabel());

			if (jumpLevel != null) {
				level = jumpLevel;
			}
			for (int i = 0; i < blocks.size(); i++) {
				TryCatchBlockNode block = blocks.get(i);

				if (block.handler.getLabel().equals(child.getLabel())) {
					level = 1;
					if (rules.isDebug()) {
						debug2("CATCH(e) -> " + blocks.peek().type);
					}
					blocks.remove(i);
					break;
				}
			}
			if (rules.isDebug()) {
				debug2("LABEL:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(LdcInsnNode child) {
			if (child.cst instanceof Long || child.cst instanceof Double) {
				level += 2;
			} else {
				level++;
			}

			if (rules.isDebug()) {
				debug2("LDC:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(LookupSwitchInsnNode child) {
			level--;

			if (rules.isDebug()) {
				debug2("LOOKUPSWITCH:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(MethodInsnNode child) {
			Type [] args = Type.getArgumentTypes(child.desc);
			Type ret = Type.getReturnType(child.desc);

			for (Type arg : args) {
				level -= arg.getSize();
			}
			switch (child.getOpcode()) {
			case Opcodes.INVOKEINTERFACE:
			case Opcodes.INVOKEVIRTUAL:
			case Opcodes.INVOKESPECIAL:
				level--;
				break;

			case Opcodes.INVOKESTATIC:
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.accept(child.owner, child.name)) {
				if (rules.isDebug()) {
					debug3(scope + " :: " + child.owner + "." + child.name + " { " + child.desc + " } : keep");
				}

				children.add(new N(level, child));
				if (ret.getSort() != Type.VOID) {
					level += ret.getSize();
				}
			} else {
//				if (rules.isDebug()) {
					info(scope + " :: " + child.owner + "." + child.name + " { " + child.desc + " } : drop");
//				}

				// pop this
				switch (child.getOpcode()) {
				case Opcodes.INVOKEINTERFACE:
				case Opcodes.INVOKEVIRTUAL:
				case Opcodes.INVOKESPECIAL:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.POP)
						)
					);
					break;
				}

				// pop args
				for (Type arg : args) {
					if (arg.getSize() == 2) {
						children.add(
							new N(
								level,
								new InsnNode(Opcodes.POP2)
							)
						);
					} else {
						children.add(
							new N(
								level,
								new InsnNode(Opcodes.POP)
							)
						);
					}
				}

				// push empty ret
				switch (ret.getSort()) {
				case Type.BOOLEAN:
				case Type.BYTE:
				case Type.CHAR:
				case Type.SHORT:
				case Type.INT:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.ICONST_0)
						)
					);
					level += 1;
					break;

				case Type.LONG:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.LCONST_0)
						)
					);
					level += 2;
					break;

				case Type.FLOAT:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.FCONST_0)
						)
					);
					level += 1;
					break;

				case Type.DOUBLE:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.DCONST_0)
						)
					);
					level += 2;
					break;

				case Type.ARRAY:
				case Type.OBJECT:
					children.add(
						new N(
							level,
							new InsnNode(Opcodes.ACONST_NULL)
						)
					);
					level += 1;
					break;
				}
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
		}

		public void add(MultiANewArrayInsnNode child) {
			level -= child.dims - 1;

			if (rules.isDebug()) {
				debug2("MULTINEWARRAY:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(TableSwitchInsnNode child) {
			level--;

			if (rules.isDebug()) {
				debug2("TABLESWITCH:level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(TryCatchBlockNode child) {
			if (rules.isDebug()) {
				debug2("TRY -> " + child.type);
			}
			blocks.add(child);
		}

		public void add(TypeInsnNode child) {
			switch (child.getOpcode()) {
			case Opcodes.NEW:
				level++;
				break;

			case Opcodes.ANEWARRAY:
			case Opcodes.CHECKCAST:
			case Opcodes.INSTANCEOF:
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}

		public void add(VarInsnNode child) {
			switch (child.getOpcode()) {
			case Opcodes.ILOAD:
			case Opcodes.FLOAD:
			case Opcodes.ALOAD:
				level++;
				break;
			case Opcodes.LLOAD:
			case Opcodes.DLOAD:
				level += 2;
				break;

			case Opcodes.ISTORE:
			case Opcodes.FSTORE:
			case Opcodes.ASTORE:
				level--;
				break;

			case Opcodes.LSTORE:
			case Opcodes.DSTORE:
				level -= 2;
				break;

			case Opcodes.RET:
				break;

			default:
				throw new RuntimeException();
			}

			if (rules.isDebug()) {
				debug2(AbstractVisitor.OPCODES[child.getOpcode()] + ":level = " + level);
			}
			children.add(new N(level, child));
		}


		public void write(MethodVisitor mv) {
			// replay instructions
			for (N child : children) {
				AbstractInsnNode node = child.node;

				if (node instanceof FieldInsnNode) {
					FieldInsnNode n = (FieldInsnNode)node;

					mv.visitFieldInsn(
						n.getOpcode(),
						n.owner,
						n.name,
						n.desc
					);
				} else if (node instanceof FrameNode) {
					FrameNode n = (FrameNode)node;
					
					mv.visitFrame(
						n.type,
						n.local.size(),
						n.local.toArray(),
						n.stack.size(),
						n.stack.toArray()
					);
				} else if (node instanceof IincInsnNode) {
					IincInsnNode n = (IincInsnNode)node;

					mv.visitIincInsn(
						n.var,
						n.incr
					);
				} else if (node instanceof IntInsnNode) {
					IntInsnNode n = (IntInsnNode)node;

					mv.visitIntInsn(
						n.getOpcode(),
						n.operand
					);
				} else if (node instanceof InsnNode) {
					InsnNode n = (InsnNode)node;

					mv.visitInsn(
						n.getOpcode()
					);
				} else if (node instanceof JumpInsnNode) {
					JumpInsnNode n = (JumpInsnNode)node;

					mv.visitJumpInsn(
						n.getOpcode(),
						n.label.getLabel()
					);
				} else if (node instanceof LabelNode) {
					LabelNode n = (LabelNode)node;

					mv.visitLabel(
						n.getLabel()
					);
				} else if (node instanceof LdcInsnNode) {
					LdcInsnNode n = (LdcInsnNode)node;

					mv.visitLdcInsn(
						n.cst
					);
				} else if (node instanceof LookupSwitchInsnNode) {
					LookupSwitchInsnNode n = (LookupSwitchInsnNode)node;
					int [] keys = new int[n.keys.size()];
					Label [] labels = new Label[n.labels.size()];

					for (int i = 0; i < n.keys.size(); i++) {
						keys[i] = (int)((Integer)n.keys.get(i));
					}
					for (int i = 0; i < n.labels.size(); i++) {
						labels[i] = ((LabelNode)n.labels.get(i)).getLabel();
					}
					mv.visitLookupSwitchInsn(
						n.dflt.getLabel(),
						keys,
						labels
					);
				} else if (node instanceof MethodInsnNode) {
					MethodInsnNode n = (MethodInsnNode)node;

					mv.visitMethodInsn(
						n.getOpcode(),
						n.owner,
						n.name,
						n.desc
					);
				} else if (node instanceof MultiANewArrayInsnNode) {
					MultiANewArrayInsnNode n = (MultiANewArrayInsnNode)node;

					mv.visitMultiANewArrayInsn(
						n.desc,
						n.dims
					);
				} else if (node instanceof TableSwitchInsnNode) {
					TableSwitchInsnNode n = (TableSwitchInsnNode)node;
					Label [] labels = new Label[n.labels.size()];

					for (int i = 0; i < n.labels.size(); i++) {
						labels[i] = ((LabelNode)n.labels.get(i)).getLabel();
					}
					mv.visitTableSwitchInsn(
						n.min,
						n.max,
						n.dflt.getLabel(),
						labels
					);
/*				} else if (node instanceof TryCatchBlockNode) {
					TryCatchBlockNode n = (TryCatchBlockNode)node;

					mv.visitTryCatchBlock(
						n.start,
						n.end,
						n.handler,
						n.type
					);*/
				} else if (node instanceof TypeInsnNode) {
					TypeInsnNode n = (TypeInsnNode)node;

					mv.visitTypeInsn(
						n.getOpcode(),
						n.desc
					);
				} else if (node instanceof VarInsnNode) {
					VarInsnNode n = (VarInsnNode)node;

					mv.visitVarInsn(
						n.getOpcode(),
						n.var
					);
				} else {
					throw new RuntimeException(scope + ": invalid instruction : " + node.getClass());
				}
			}
		}


		private static class N {
			public int level;

			public AbstractInsnNode node;


			public N(int level, AbstractInsnNode node) {
				this.level = level;
				this.node = node;
			}
		}
	}
}
