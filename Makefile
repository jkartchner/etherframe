CC=gcc
CFLAGS=-I.
DEPS = efunctions.h arpsend.h arpois.h netjack.h

ODIR=obj

# here we define 1) where to take c files from (the current directory)
# and 2) where to place the object files 
# and 3) a variable referencing the object files for use later in makefile
# note: this can be done 4 any variable elsewhere (e.g., DEPS include folder)
_OBJ = eframe.o efunctions.o arpsend.o arpois.o netjack.o
OBJ = $(patsubst %, $(ODIR)/%,$(_OBJ))

# this rule ensures all c files are compiled to object files
# the $(ODIR)/ places the object files in the ODIR folder
$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

# this rule is the compilation rule; $@ = eframe; $^ = $(OBJ)
eframe: $(OBJ)
	$(CC) -pthread -o $@ $^ $(CFLAGS)

.PHONY: clean

# this I still don't understand completely; look up syntax man Makefile
clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~

#http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
#	This addition first creates the macro DEPS, which is the set of .h files on which the .c files depend. Then we define a rule that applies to all files ending in the .o suffix. The rule says that the .o file depends upon the .c version of the file and the .h files included in the DEPS macro. The rule then says that to generate the .o file, make needs to compile the .c file using the compiler defined in the CC macro. The -c flag says to generate the object file, the -o $@ says to put the output of the compilation in the file named on the left side of the :, the $< is the first item in the dependencies list, and the CFLAGS macro is defined as above.

#	As a final simplification, let's use the special macros $@ and $^, which are the left and right sides of the :, respectively, to make the overall compilation rule more general. In the example below, all of the include files should be listed as part of the macro DEPS, and all of the object files should be listed as part of the macro OBJ.
