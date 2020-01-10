CC	= gcc

CFLAGS	+= -Wall -g -std=gnu99 -O2 -Iinclude -I.
LDFLAGS	+=

NAME	= mtsk
SRCS	:= mtsk.c socket.c md5.c hex.c stringlist.c ../threadpool/threadpool.c
OBJS	:= $(SRCS:%.c=obj/%.o)

all: dirs $(NAME)

dirs:
	mkdir -p obj

$(NAME): $(OBJS)
	@$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "Linking complete!"

$(OBJS): obj/%.o : src/%.c
	@$(CC) $(USER_DEFINES) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: install
install: $(NAME)
	mkdir -p $(DESTDIR)$(PREFIX)$(BINDIR)
	cp $(NAME) $(DESTDIR)$(PREFIX)$(BINDIR)/$(NAME)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(BINDIR)/$(NAME)
