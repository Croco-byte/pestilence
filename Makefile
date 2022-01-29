# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: user42 <user42@student.42.fr>              +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/01/25 13:17:10 by user42            #+#    #+#              #
#    Updated: 2022/01/25 13:18:32 by user42           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Pestilence

LD = ld
NASM = nasm

SRCS =	$(addsuffix .asm, $(addprefix srcs/, pestilence))

OBJS = ${SRCS:.asm=.o}

all:		$(NAME)

$(NAME):	$(OBJS)
			$(LD) -o $(NAME) $(OBJS)

%.o:%.asm
			$(NASM) -f elf64 -i srcs/ $< -o $@

clean:
				rm -f $(OBJS)

fclean:
				rm -f $(OBJS)
				rm -f $(NAME)

re:				fclean all

.PHONY:			all clean fclean re
