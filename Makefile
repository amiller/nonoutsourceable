CC=gcc -g
CFLAGS=-DQSP_NATIVE -DBRANCHES_PER_CIRCUIT=$(B) -DTREE1_HEIGHT=$(H)
LIBS=
DEPS = *.h
SERVER=ec2-winbig

all: B=1
all: H=10
all: scratch_test_circuit_1 scratch_test_circuit_2 stB0


stB0: CIRCUIT_NUMBER=0
stB0: scratch_test_circuitB_1

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

scratch_test_circuit_1: scratch_test_circuit_1.o scratch_circuit_1.o sha1.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

scratch_test_circuit_2: scratch_test_circuit_2.o scratch_circuit_2.o sha1.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

scratch_test_circuitB_1: scratch_test_circuitB_1.o scratch_circuitB_1.o sha1.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

pinocchio1: 
	python ~/vc/pinocchio/ccompiler/src/vercomp.py --il ./scratch_circuit_1.il --arith ./scratch_circuit_1.arith ./scratch_circuit_1.c --progress=True --bit-width=32 2>&1 | tee output.log
# --ignore-overflow=False

.PHONY: clean

clean:
	rm -f *.o *~

remote_compile_:
	sshpass -p $(PASSWORD) rsync *.c *.h Administrator@$(SERVER):Desktop/vc/
	sshpass -p $(PASSWORD) ssh Administrator@$(SERVER) "bash -c 'cd Desktop/vc/; python pinocchio/ccompiler/src/vercomp.py --il ./scratch_circuit_$(C)_b$(B)_h$(H).il --arith ./scratch_circuit_$(C)_b$(B)_h$(H).arith ./scratch_circuit_$(C).c --progress=True --bit-width=32 --cpparg _DBRANCHES_PER_CIRCUIT=$(B) _DTREE1_HEIGHT=$(H) | grep mul'"
	sshpass -p 4netB3kvX6 rsync Administrator@$(SERVER):Desktop/vc/scratch_circuit_$(C)_b$(B)_h$(H).arith .

# Inner circuits
remote_compile_1_1_10: TESTDIR=test_ticket_b01_h10_q110_q210
remote_compile_1_1_10: B=1
remote_compile_1_1_10: H=10
remote_compile_1_1_10: C=1
remote_compile_1_1_10: remote_compile_

remote_compile_1_2_10: B=2
remote_compile_1_2_10: H=10
remote_compile_1_2_10: C=1
remote_compile_1_2_10: TESTDIR=test_ticket_b02_h10_q110_q210
remote_compile_1_2_10: remote_compile_

remote_compile_1_2_11: B=2
remote_compile_1_2_11: H=11
remote_compile_1_2_11: C=1
remote_compile_1_2_11: TESTDIR=test_ticket_b02_h11_q110_q210
remote_compile_1_2_11: remote_compile_

# Final circuit
remote_compile_2_1_10: TESTDIR=test_ticket_b01_h10_q110_q210
remote_compile_2_1_10: B=1
remote_compile_2_1_10: H=10
remote_compile_2_1_10: C=2
remote_compile_2_1_10: remote_compile_

remote_compile_2_2_10: B=2
remote_compile_2_2_10: H=10
remote_compile_2_2_10: C=2
remote_compile_2_2_10: TESTDIR=test_ticket_b02_h10_q110_q210
remote_compile_2_2_10: remote_compile_

remote_compile_2_2_11: B=2
remote_compile_2_2_11: H=11
remote_compile_2_2_11: C=2
remote_compile_2_2_11: TESTDIR=test_ticket_b02_h11_q110_q210
remote_compile_2_2_11: remote_compile_

#$(SERVER)
#$(SERVER)big
remote_execute_:
remote_execute_:
	sshpass -p 4netB3kvX6 rsync -r $(TESTDIR) scratch_circuit_1_b$(B)_h$(H).arith Administrator@$(SERVER):Desktop/vc/
	sshpass -p 4netB3kvX6 ssh Administrator@$(SERVER) "bash -c 'cd Desktop/vc/; pinocchio/pinocchio-current.exe --file scratch_circuit_1_b$(B)_h$(H).arith --input $(TESTDIR)/wire_input_00.in --pv --output $(TESTDIR)/output_00.out --qap --mem 240 --pcache --fill'"
	sshpass -p 4netB3kvX6 rsync -r Administrator@$(SERVER):Desktop/vc/$(TESTDIR)/output_00.out $(TESTDIR)/
	cat $(TESTDIR)/output_00.out

remote_execute_1_10: B=1
remote_execute_1_10: H=10
remote_execute_1_10: TESTDIR=test_ticket_b01_h10_q110_q210
remote_execute_1_10: remote_execute_

remote_execute_1_11: B=1
remote_execute_1_11: H=11
remote_execute_1_11: TESTDIR=test_ticket_b01_h11_q110_q210
remote_execute_1_11: remote_execute_

remote_execute_2_11: B=2
remote_execute_2_11: H=11
remote_execute_2_11: TESTDIR=test_ticket_b02_h11_q110_q210
remote_execute_2_11: remote_execute_

sha:
	python ~/vc/pinocchio/ccompiler/src/vercomp.py --il ~/vc/pinocchio/ccompiler/input/build/sha.il --arith ~/vc/pinocchio/ccompiler/input/build/sha.arith ~/vc/pinocchio/ccompiler/input/sha.c --progress=True --bit-width=32 --cpparg _Ibuild/ _DPARAM=1 2>&1 | tee output.log
	sshpass -p 4netB3kvX6 rsync -r ~/vc/pinocchio/ccompiler/input/build/sha.arith Administrator@$(SERVER):Desktop/vc/
	sshpass -p 4netB3kvX6 ssh Administrator@$(SERVER) "bash -c 'cd Desktop/vc/; pinocchio/pinocchio-current.exe --file sha.arith --input sha.in --pv --output sha.out --qap --mem 20 --pcache'"
	sshpass -p 4netB3kvX6 rsync -r Administrator@$(SERVER):Desktop/vc/sha.out ./
	cat sha.out

remote_execute2_:
	sshpass -p 4netB3kvX6 rsync -r $(TESTDIR) merged_deffie_hellman_scratch_circuit.arith Administrator@$(SERVER):Desktop/vc/
	sshpass -p 4netB3kvX6 ssh Administrator@$(SERVER) "bash -c 'cd Desktop/vc/; pinocchio/pinocchio-current.exe --file merged_deffie_hellman_scratch_circuit.arith --bits 32 --pv --output $(TESTDIR)/output_final.out --nizk --qap --mem 240 --pcache'"
	sshpass -p 4netB3kvX6 rsync -r Administrator@$(SERVER):Desktop/vc/$(TESTDIR)/output_final.out $(TESTDIR)/
	cat $(TESTDIR)/output_final.out

